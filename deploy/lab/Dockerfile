# Obraz programu serwera SIEM. Binarium budowane wcześniej
# (GOOS=linux GOARCH=amd64 CGO_ENABLED=0) i kopiowane do ./bin.
FROM gcr.io/distroless/static-debian12:nonroot
ARG BIN
# --chmod: plik wgrany z Windows (scp) nie ma prawa wykonania.
COPY --chmod=0755 bin/${BIN} /app
ENTRYPOINT ["/app"]
