project('libfprint-tod-tdk5812', 'c', 'cpp',
  version: '0.2.0',
  license: 'LGPL-2.1-or-later',
  meson_version: '>= 0.60',
  default_options: ['c_std=gnu11', 'cpp_std=c++17', 'warning_level=2', 'buildtype=debugoptimized'])

tod = dependency('libfprint-2-tod-1')
cxx = meson.get_compiler('cpp')

opencv = dependency('opencv4', required: false)
if not opencv.found()
  # Debian/Ubuntu ship opencv4.pc only in the big libopencv-dev metapackage
  opencv = declare_dependency(
    include_directories: include_directories('/usr/include/opencv4', is_system: true),
    dependencies: [cxx.find_library('opencv_core'), cxx.find_library('opencv_imgproc'),
                   cxx.find_library('opencv_features2d'), cxx.find_library('opencv_calib3d')])
endif

fw_path = get_option('firmware_path')

shared_module('fprint-tod-tdk5812',
  'src/tdk5812.c', 'src/tdkmatch.cpp',
  dependencies: [
    tod,
    dependency('libfprint-2'),
    dependency('glib-2.0'),
    dependency('gobject-2.0'),
    dependency('gusb'),
    dependency('libcrypto'),
    opencv,
  ],
  c_args: ['-Wno-unused-parameter', '-Wno-missing-field-initializers',
           '-DTDK5812_FW_PATH="@0@"'.format(fw_path)],
  cpp_args: ['-Wno-unused-parameter'],
  install: true,
  install_dir: tod.get_variable(pkgconfig: 'tod_driversdir'))

summary({
  'TOD drivers dir': tod.get_variable(pkgconfig: 'tod_driversdir'),
  'firmware path': fw_path,
})
