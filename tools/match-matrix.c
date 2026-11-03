/* build: g++ -O2 -o match-matrix match-matrix.c ../src/tdkmatch.cpp -I/usr/include/opencv4 \
 *        -lopencv_core -lopencv_imgproc -lopencv_features2d -lopencv_calib3d
 * usage: match-matrix img.pgm... > scores.txt
 * score matrix with the driver's C++ matcher: rows=template, cols=probe */
#include "../src/tdkmatch.h"
#include <stdio.h>
#include <stdlib.h>
int main (int argc, char **argv)
{
  int n = argc - 1;
  tdk_feat **f = (tdk_feat **) calloc (n, sizeof *f);
  static unsigned char px[135 * 62];
  for (int i = 0; i < n; i++)
    {
      FILE *fp = fopen (argv[i + 1], "rb");
      fseek (fp, -135 * 62, SEEK_END);
      if (fread (px, 1, sizeof px, fp) != sizeof px) return 1;
      fclose (fp);
      f[i] = tdk_feat_new (px, 135, 62);
    }
  for (int i = 0; i < n; i++)
    {
      for (int j = 0; j < n; j++)
        printf ("%d ", i == j ? 0 : tdk_feat_score (f[j], f[i]));
      printf ("\n");
    }
  return 0;
}
