# selfdef umask-baseline — group profile. /etc/profile.d sourced
# by every interactive shell at login time.
#
# umask 0027:
#   owner = rwx (7)
#   group = r-x (5)
#   world = --- (0)
#
# Files created by the operator are NOT world-readable by default.
# Reduces information-leak surface (operator's hand-written
# scripts in $HOME, downloaded files, etc.).
umask 0027
