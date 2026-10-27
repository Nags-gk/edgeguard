# Connect EdgeGuard to Microsoft Entra ID

EdgeGuard validates real Entra access tokens (v1 or v2) against your tenant's OIDC signing keys and reads
**app roles** as groups. One app registration serves both the console (SPA sign-in) and the API.

1. **Register the app.** Entra admin center → *Identity → Applications → App registrations → New registration*.
   Name `EdgeGuard`, *Accounts in this organizational directory only*. Note the **Application (client) ID**
   and **Directory (tenant) ID**.
2. **Expose an API.** *Expose an API* → set the Application ID URI to `api://<client-id>` → *Add a scope*
   named `access_as_user` (admins and users can consent).
3. **Use v2 tokens.** *Manifest* → set `"requestedAccessTokenVersion": 2` (Microsoft Graph manifest:
   `api.requestedAccessTokenVersion`).
4. **Create app roles** (*App roles → Create app role*, allowed member types *Users/Groups*), values exactly:
   `Employees`, `HR`, `Finance`, `Security`, `Contractors`.
5. **Add the SPA platform.** *Authentication → Add a platform → Single-page application*, redirect URIs:
   `https://<your-cloud-run-url>/` and `http://localhost:8080/`.
6. **Assign yourself roles.** *Enterprise applications → EdgeGuard → Users and groups → Add user/group*.
   Assign `Employees` (and `HR` to see the HR Portal open up).
7. **Deploy with Entra on:**
   ```bash
   ENTRA_TENANT_ID=<tenant-id> ENTRA_CLIENT_ID=<client-id> PROJECT=<gcp-project> bash deploy/cloudrun.sh
   ```

**MFA signal.** Policies that require MFA read the token's `amr` claim (`mfa`) or a Conditional Access
authentication context (`acrs` = `c1`). To satisfy them with a real account, create a Conditional Access
policy that requires MFA for the EdgeGuard app, or an authentication context `c1`.

**Device signal.** Device compliance comes from a signed device token. In this demo the demo issuer signs
it; in production it would come from a device-management attestation (for example Intune compliance),
which is out of scope here.
