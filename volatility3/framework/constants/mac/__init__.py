# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""Volatility 3 Mac Constants.

Darwin-specific values that aren't found in debug symbols
"""

# Address families
# ref: bsd/sys/socket.h
#
# These are the values stored inside macOS memory images. They are not
# interchangeable with the analysis host's socket.AF_* constants: AF_INET6 is
# 10 on Linux, 23 on Windows and 30 on macOS. Any code decoding a macOS image
# must compare against these constants rather than the host's.
AF_UNSPEC = 0
AF_UNIX = 1
AF_INET = 2
AF_LINK = 18
AF_INET6 = 30
