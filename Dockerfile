FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY Gateway.sln ./
COPY src/Gateway.Api/Gateway.Api.csproj src/Gateway.Api/
COPY nuget.config ./
COPY local-feed/ local-feed/
RUN dotnet restore src/Gateway.Api/Gateway.Api.csproj
COPY . .
RUN dotnet publish src/Gateway.Api/Gateway.Api.csproj -c Release -o /app/publish /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app
EXPOSE 5000
ENV ASPNETCORE_URLS=http://+:5000
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
USER app
COPY --from=build /app/publish .
HEALTHCHECK --interval=10s --timeout=3s --retries=5 CMD curl -f http://localhost:5000/health || exit 1
ENTRYPOINT ["dotnet", "Gateway.Api.dll"]
