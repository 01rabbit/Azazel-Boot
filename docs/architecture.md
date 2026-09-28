# Architecture and scope

Status: **owner-approved direction; implementation not specified**.

## Product role

Azazel-Boot is a user-assistance and optional tool-installation companion that
runs within an operating environment supplied and started by the user. Boot
does not produce that environment. It does not build or remaster Debian Live,
select an image builder, create boot media, write an image, or own a boot-time
initramfs path.

Boot is not a second Nexus installer. Nexus owns installation and integration
of the persistent gateway appliance. A future Boot helper may guide the user
through installing or using a narrowly scoped set of tools that distinguish
Boot's responder workflow from Nexus. The tool inventory and installation
contract remain undecided; no operational installer is authorized by this
document.

## Authority and side effects

Fabric describes. Knowledge advises. Azazel-Edge decides and enforces. Boot
does not create another decision, trust, provider-admission, or enforcement
authority. A Boot user interface can present a plan and record a user's choice;
it cannot turn that choice into Edge policy or activate an Edge workload.

No image or media writer belongs in Boot. A future tool installer must declare
its exact package inputs, target paths, privilege needs, network behavior, and
rollback limits before implementation. It may not silently modify unrelated
host state. Explicit user authorization is required for any host changes.

## Boundaries with neighboring products

- **Azazel-Nexus:** persistent gateway appliance and its base installer. Boot
  must not duplicate that installation flow.
- **Azazel-Edge:** owns deterministic decisions and enforcement. Boot does not
  invoke Edge's device-specific network installer or substitute for Edge.
- **Azazel-Fabric:** shared contract source. A future Boot helper may consume
  released contracts if its design requires them; the current package pins no
  Fabric version and defines no Boot-local canonical contract.
- **Azazel-Boot:** user-facing guidance and, only after separate approval, a
  bounded tool-installation helper.

## Deferred design questions

These are implementation prerequisites, not permission to invent a solution:

1. Which concrete responder tools are distinct from Nexus and owned by Boot?
2. Which pre-existing host environments are supported?
3. Are inputs offline bundles, signed packages, or both, and which authority
   owns their admission?
4. What exact host changes are permitted, and how are approval, rollback, and
   uninstall represented?
5. What evidence proves that an installation succeeded without implying
   provider admission, model acquisition, or Edge activation?

The next work is to answer only the questions needed for one concrete helper,
then implement and test that helper. No builder, writer, disk-layout, firmware,
Secure Boot, initramfs-quarantine, or encrypted-Boot-persistence work is in the
current backlog.
