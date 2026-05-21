# selfdef umask-baseline — strict profile. /etc/profile.d sourced
# by every interactive shell at login time.
#
# umask 0077:
#   owner = rwx (7)
#   group = --- (0)
#   world = --- (0)
#
# Files created by the operator are owner-readable only. Highest-
# assurance default for hosts where group-based sharing isn't
# operator-meaningful.
umask 0077
