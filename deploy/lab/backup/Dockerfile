# Usługa kopii zapasowych (siem-backup): pg_dump z tej samej wersji co Saga,
# gpg (szyfrowanie jak backup.sh), rclone (SFTP, SMB, S3), ssh-keygen.
FROM postgres:18-alpine
RUN apk add --no-cache gnupg rclone openssh-client tar
COPY --chmod=0755 bin/siem-backup /usr/local/bin/siem-backup
ENTRYPOINT ["siem-backup"]
CMD ["serve"]
