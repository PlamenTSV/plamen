# Medusa v1.5.1 native-image input

Medusa is a setup-time source input, never an audit-time download or Go build.
The reviewed policy is `verification_policy/medusa_acquisition.v1.json` with
SHA-256 `4112703567b4c398207eaf09c75503840704be44b663a43e82fae42aa32a0208`.

Primary upstream evidence (observed 2026-09-14):

- GitHub release API: <https://api.github.com/repos/crytic/medusa/releases/tags/v1.5.1>
- GitHub release: <https://github.com/crytic/medusa/releases/tag/v1.5.1>
- Linux x64 asset: <https://github.com/crytic/medusa/releases/download/v1.5.1/medusa-linux-x64.tar.gz>
- Sigstore bundle: <https://github.com/crytic/medusa/releases/download/v1.5.1/medusa-linux-x64.tar.gz.sigstore.json>

The API records release ID `295655662`, archive asset ID `371539722`, archive
SHA-256 `ddfe1517ae9028ef9fc331b00f5a6a9d5406f3fcd11a715d60c6b6fb3e4546d3`,
and archive size `11948454`. The bundle is asset ID `371539721`, SHA-256
`e7a277b17588fe02425a0cf4656f36d98f39eea9d4a7b0548e6617184238efb6`,
and size `10584`.

The archive has one member, `medusa`. That ELF x86-64 executable is 23,748,448
bytes with SHA-256
`86e54c586e49e6bf9676f448218e10475afacb0a8bd5ca1aea234f66db7169d6`.
Its Go build information binds module `github.com/crytic/medusa` at `v1.5.1`.
The exact Sigstore bundle binds the GitHub Actions certificate identity
`https://github.com/crytic/medusa/.github/workflows/ci.yml@refs/tags/v1.5.1`,
OIDC issuer `https://token.actions.githubusercontent.com`, and source commit
`540a483b7a2a35b0a6d210aeb6ae6015aa7a0f62`.

The executable is materialized as role `medusa` at
`/usr/local/lib/plamen/toolchains/medusa/bin/medusa`, mode `0555`, platform
`linux/amd64`, with Rosetta required in Apple Container. The native source
bootstrap coordinator must authenticate retained archive, Sigstore bundle,
policy, and extracted executable identities and issue its signed producer
receipt before operation 4. Until that generic coordinator exists, this input
remains unavailable; Python policy validation is not production authority.
