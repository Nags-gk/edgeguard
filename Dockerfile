# syntax=docker/dockerfile:1
# One image, two processes: Envoy (data path, :8080) in front of the C# authz service.
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY src/EdgeGuard.Authz/EdgeGuard.Authz.csproj src/EdgeGuard.Authz/
RUN dotnet restore src/EdgeGuard.Authz/EdgeGuard.Authz.csproj
COPY src/ src/
RUN dotnet publish src/EdgeGuard.Authz/EdgeGuard.Authz.csproj -c Release -o /out --no-restore

FROM envoyproxy/envoy:v1.33-latest AS envoy

FROM mcr.microsoft.com/dotnet/aspnet:8.0
COPY --from=envoy /usr/local/bin/envoy /usr/local/bin/envoy
WORKDIR /app
COPY --from=build /out ./
COPY envoy/envoy.yaml /etc/envoy/envoy.yaml
COPY deploy/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && useradd --system --uid 10001 edgeguard && chown -R edgeguard /app
USER 10001
ENV ASPNETCORE_ENVIRONMENT=Production \
    EdgeGuard__PolicyPath=/app/config/policy.json \
    DOTNET_gcServer=0
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s CMD ["/bin/sh","-c","exec 3<>/dev/tcp/127.0.0.1/8080"]
ENTRYPOINT ["/entrypoint.sh"]
