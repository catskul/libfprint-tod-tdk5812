"""Keypoint + geometric-consistency matcher evaluation (SIGFM-style).
usage: python3 feat_eval.py <data_dir> [upscale] [ratio]
"""
import glob
import os
import sys
import numpy as np
import cv2

DATA = sys.argv[1]
UP = float(sys.argv[2]) if len(sys.argv) > 2 else 2.0
RATIO = float(sys.argv[3]) if len(sys.argv) > 3 else 0.80


def load(p):
    a = np.frombuffer(open(p, "rb").read()[-135 * 62:], np.uint8).reshape(62, 135)
    a = cv2.resize(a, None, fx=UP, fy=UP, interpolation=cv2.INTER_CUBIC)
    a = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(4, 4)).apply(a)
    return a


sift = cv2.SIFT_create(contrastThreshold=0.02, edgeThreshold=10)
files = sorted(glob.glob(os.path.join(DATA, "*.pgm")))
labels = [os.path.basename(f).rsplit("_", 1)[0] for f in files]
feats = []
for f in files:
    kp, des = sift.detectAndCompute(load(f), None)
    feats.append((kp, des))
print("keypoints per image: median %d min %d" % (np.median([len(k) for k, _ in feats]), min(len(k) for k, _ in feats)))
bf = cv2.BFMatcher(cv2.NORM_L2)


def score(a, b):
    ka, da = feats[a]
    kb, db = feats[b]
    if da is None or db is None or len(ka) < 3 or len(kb) < 3:
        return 0
    good = []
    for m in bf.knnMatch(da, db, k=2):
        if len(m) == 2 and m[0].distance < RATIO * m[1].distance:
            good.append(m[0])
    if len(good) < 3:
        return 0
    pa = np.float32([ka[m.queryIdx].pt for m in good])
    pb = np.float32([kb[m.trainIdx].pt for m in good])
    M, inl = cv2.estimateAffinePartial2D(pa, pb, method=cv2.RANSAC, ransacReprojThreshold=3.0 * UP / 2,
                                         maxIters=2000, confidence=0.99)
    if M is None:
        return 0
    s = np.hypot(M[0, 0], M[1, 0])
    if not 0.85 < s < 1.15:      # same sensor: no real scale change
        return 0
    return int(inl.sum())


n = len(files)
S = np.zeros((n, n))
for i in range(n):
    for j in range(n):
        if i != j:
            S[i, j] = score(j, i)   # probe j vs template i
gi = [i for i, l in enumerate(labels) if l == "right-index"]
imp = [j for j, l in enumerate(labels) if l != "right-index"]
rng = np.random.default_rng(1)
gs, ims = [], []
for _ in range(300):
    perm = rng.permutation(gi)
    enr, test = perm[:12], perm[12:]
    gs += [max(S[i, j] for i in enr) for j in test]
    ims += [max(S[i, j] for i in enr) for j in imp]
gs, ims = np.array(gs), np.array(ims)
print(f"genuine verify: min {gs.min():.0f} p5 {np.percentile(gs,5):.0f} median {np.median(gs):.0f}")
print(f"impostor verify: max {ims.max():.0f} p99 {np.percentile(ims,99):.0f} median {np.median(ims):.0f}")
for t in range(4, 26, 2):
    print(f"  inliers>={t:2d}: FRR {np.mean(gs < t)*100:5.1f}%  FAR {np.mean(ims >= t)*100:5.2f}%")
print("worst impostors:", sorted(((S[gi, j].max(), os.path.basename(files[j])) for j in imp), reverse=True)[:5])
np.save(os.path.join(DATA, "..", "feat_scores.npy"), S)
