#pragma once

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tdk_feat tdk_feat;

/* img: native 8-bit sensor image (unstretched), row-major w x h */
tdk_feat *tdk_feat_new (const unsigned char *img, int w, int h);
int       tdk_feat_count (const tdk_feat *f);
int       tdk_feat_score (const tdk_feat *probe, const tdk_feat *tmpl);  /* RANSAC inliers */
void      tdk_feat_free (tdk_feat *f);

#ifdef __cplusplus
}
#endif
