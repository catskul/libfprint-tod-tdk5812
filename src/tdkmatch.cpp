/*
 * Small-area fingerprint matcher for the tdk5812 driver: SIFT keypoints on a CLAHE-enhanced,
 * 2x-upscaled image; ratio-test matching; RANSAC similarity transform; score = inlier count.
 * Parameters match tools/feat_eval.py (evaluated on collected data: impostor max 4 inliers).
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#include "tdkmatch.h"

#include <opencv2/core.hpp>
#include <opencv2/imgproc.hpp>
#include <opencv2/features2d.hpp>
#include <opencv2/calib3d.hpp>
#include <cmath>
#include <new>
#include <vector>

struct tdk_feat
{
  std::vector<cv::KeyPoint> kp;
  cv::Mat                   des;
};

extern "C" tdk_feat *
tdk_feat_new (const unsigned char *img, int w, int h)
{
  try
    {
      cv::Mat src (h, w, CV_8UC1, const_cast<unsigned char *> (img));
      cv::Mat up, enh;
      cv::resize (src, up, cv::Size (), 2.0, 2.0, cv::INTER_CUBIC);
      cv::createCLAHE (2.0, cv::Size (4, 4))->apply (up, enh);

      static thread_local cv::Ptr<cv::SIFT> sift = cv::SIFT::create (0, 3, 0.02, 10);
      tdk_feat *f = new tdk_feat;
      sift->detectAndCompute (enh, cv::noArray (), f->kp, f->des);
      return f;
    }
  catch (...)
    {
      return nullptr;
    }
}

extern "C" int
tdk_feat_count (const tdk_feat *f)
{
  return f ? (int) f->kp.size () : 0;
}

extern "C" void
tdk_feat_free (tdk_feat *f)
{
  delete f;
}

extern "C" int
tdk_feat_score (const tdk_feat *probe, const tdk_feat *tmpl)
{
  if (!probe || !tmpl || probe->kp.size () < 3 || tmpl->kp.size () < 3 ||
      probe->des.empty () || tmpl->des.empty ())
    return 0;
  try
    {
      cv::BFMatcher bf (cv::NORM_L2);
      std::vector<std::vector<cv::DMatch>> knn;
      bf.knnMatch (probe->des, tmpl->des, knn, 2);

      std::vector<cv::Point2f> pa, pb;
      for (const auto &m : knn)
        if (m.size () == 2 && m[0].distance < 0.80f * m[1].distance)
          {
            pa.push_back (probe->kp[m[0].queryIdx].pt);
            pb.push_back (tmpl->kp[m[0].trainIdx].pt);
          }
      if (pa.size () < 3)
        return 0;

      cv::Mat inl;
      cv::setRNGSeed (12345);  /* deterministic RANSAC */
      cv::Mat M = cv::estimateAffinePartial2D (pa, pb, inl, cv::RANSAC, 3.0, 2000, 0.99);
      if (M.empty ())
        return 0;
      double s = std::hypot (M.at<double> (0, 0), M.at<double> (1, 0));
      if (s < 0.85 || s > 1.15)  /* same sensor: no real scale change */
        return 0;
      return cv::countNonZero (inl);
    }
  catch (...)
    {
      return 0;
    }
}
