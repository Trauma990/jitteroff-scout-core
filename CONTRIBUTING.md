# Contributing

Open an issue before broad architecture changes. Keep the core independent of any vendor's private service, account system, packet captures or customer data. Add focused tests for parser, address policy, TLS, HTTP and report behavior. Run `dotnet restore --locked-mode`, `dotnet build --no-restore` and `dotnet test --no-restore` before a pull request. Never commit credentials, private hostnames, IP inventories, production logs or customer reports. Security findings follow [SECURITY.md](SECURITY.md).

The maintainer reviews licensing and provenance for every imported dependency or code fragment. Contributors certify that they have rights to submit their work under Apache-2.0.
