\# Active Directory Recursive Group Membership Tree Visualization Engine



An advanced enterprise auditing and infrastructure utility engineered to map, trace, and visualize complex hierarchical nested group memberships across multi-domain Active Directory forests. The engine bypasses standard LDAP reporting limitations by resolving indirect memberships and dynamic Primary Groups via algorithmic SID manipulation, outputting detailed flat relational files (.csv) alongside structural ASCII tree layouts (.txt).



\## 🌟 Advanced Technical Highlights



\* \*\*Dynamic Primary Group Translation Engine:\*\* Overcomes native Active Directory limitations where default cmdlets omit primary group memberships (e.g., Domain Users) from an object's `memberOf` array. The utility reconstructs security strings mathematically by parsing the user's `objectSid` byte array and relative identifier (RID) `primaryGroupID` into an explicit object SID.

\* \*\*Cycle-Safe Graph Traversal Recursion:\*\* Implements an optimized Depth-First Search (DFS) algorithm backed by a native `.NET` `\[System.Collections.Generic.HashSet\[string]]` tracking map. This enforces strict execution constraints that prevent infinite loops and graph cycle crashes caused by circular group nesting across multi-forest trust environments.

\* \*\*Global Catalog \& Forest Ingestion Routing:\*\* Automatically interrogates the Active Directory forest schema topology. If an object's home domain cannot be identified within the local trust layer, the engine automatically falls back to intercept and query Global Catalog servers via port `3268` to resolve cross-domain LDAP objects.

\* \*\*Synchronized Telemetry Output Delivery:\*\* Orchestrates multi-format reporting simultaneously. It isolates explicit relational membership strings into structured, clean data matrices (.csv) while compiling recursive inheritance strings into human-readable text hierarchies (.txt) that auto-spawns via native Windows subsystem handlers.



\---



\## 🛠️ Technology Core



\* \*\*Automation Engine:\*\* PowerShell 5.1 / Core

\* \*\*Directory Protocols:\*\* Active Directory LDAP Architecture (Forest/Global Catalog Topology Integration)

\* \*\*API Ingestion Framework:\*\* Microsoft.ActiveDirectory.Management

\* \*\*Data Typology \& Classes:\*\* System.Collections.Generic.HashSet, System.Collections.Generic.List, System.IO.Path



\---



\## 📐 Pipeline \& Processing Workflow



1\. \*\*Target Identity Sanitization:\*\* Captures target string identities (SAMAccountNames/UPNs) and handles string sanitization to strip away terminal escape characters or illegal formatting artifacts.

2\. \*\*Directory Resolution \& Home-Domain Evaluation:\*\* Traverses all discovered forest domain components to safely lock down the explicit target security account.

3\. \*\*Primary Group Mapping \& Extraction:\*\* Evaluates SID byte arrays to resolve dynamic structural group assets missing from core array attributes.

4\. \*\*Recursive Depth Mapping Expansion:\*\* Triggers the cycle-safe graph walker, resolving indirect parental inheritance paths across the directory landscape.

5\. \*\*Simultaneous File System Export:\*\* Compiles flat structured data alongside textual hierarchy trees into the host's `%TEMP%` environment variables, immediately executing local subsystem handlers (Notepad/Excel) for administrative triage.



\---



\## 🚀 Local Deployment



\### Prerequisites

\* Running an elevated terminal session (Run as Administrator).

\* Workstation equipped with Remote Server Administration Tools (RSAT) Active Directory PowerShell components or a direct line of sight to a functional Domain Controller.



\### Execution

1\. Initialize the auditor script from an elevated prompt:

```powershell

&#x20;  \& .\\Get-NestedMemberships.ps1

