# Narzędzie wixl (msitools) do budowania instalatora MSI agenta na Linuksie.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends wixl msitools && rm -rf /var/lib/apt/lists/*
WORKDIR /w
ENTRYPOINT ["wixl"]
