# Risk Analysis

## Assumptions

This risk assessment assumes the infant incubator application is deployed on a networked system with standard operating system security protections. Authorized users access the system through authenticated client devices, and the application may be remotely accessible for monitoring and management. These assumptions are used when evaluating the likelihood and impact of each threat.

### Threat 1 – User Credentials Disclosed

**Likelihood:** Medium. An attacker would need access to network traffic, stored credentials, or a user's device to obtain login credentials. While modern systems typically provide security protections, weak password storage or unencrypted communication could expose user credentials.

**Impact:** High. If an attacker obtains valid user credentials, they can authenticate as a legitimate user and gain unauthorized access to the incubator system. This could allow them to view sensitive information or issue unauthorized commands.

**Risk:** A medium likelihood combined with a high impact results in a **Medium** risk. We agree with this risk rating because credential theft requires some attacker capability, but the consequences of a successful attack are significant.

---

### Threat 2 – Authentication Token Capture

**Likelihood:** High. If authentication tokens are not adequately protected (for example, transmitted without encryption or stored insecurely), an attacker monitoring network traffic or compromising a client device could capture them without needing the user's password.

**Impact:** Critical. A stolen authentication token allows an attacker to impersonate a legitimate user immediately. This could provide unrestricted access to system functions and allow malicious changes to the incubator settings.

**Risk:** A high likelihood combined with a critical impact results in a **Critical** risk. We agree with this risk rating because compromised authentication tokens can provide immediate unauthorized access to the system.

---

### Threat 3 – Physical Power Interruption

**Likelihood:** Low. A power interruption would generally require physical access, deliberate sabotage, or failure of the facility's electrical infrastructure. These attacks are more difficult to perform than remote attacks.

**Impact:** Critical. Interrupting power could stop the application and prevent monitoring or control of the infant incubator, potentially creating dangerous conditions for the patient.

**Risk:** A low likelihood combined with a critical impact results in a **Medium** risk. We agree with this risk rating because although physical attacks are less common, the consequences of a successful attack could be severe.

---

### Threat 4 – Distributed Denial-of-Service (DDoS)

**Likelihood:** Medium. If the application is accessible from the Internet, it may become a target of denial-of-service attacks. Attackers can use compromised devices to overwhelm the server with traffic, making the application unavailable.

**Impact:** High. A successful DDoS attack could prevent authorized users from accessing the system, interrupting monitoring and management of the infant incubator.

**Risk:** A medium likelihood combined with a high impact results in a **Medium** risk. We agree with this risk rating because service disruptions are realistic threats, although they generally do not compromise sensitive data directly.

---

### Threat 5 – Unauthorized Modification of Incubator Controls

**Likelihood:** Medium. An attacker would first need to compromise an administrator account or exploit another vulnerability to gain sufficient privileges before issuing malicious commands.

**Impact:** Critical. Altering incubator temperature or other environmental controls could directly endanger the infant by creating unsafe operating conditions.

**Risk:** A medium likelihood combined with a critical impact results in a **High** risk. We agree with this risk rating because although privileged access is required, the potential impact on patient safety is extremely serious.

---

### Threat 6 – Disruption of Infant Safety Components

**Likelihood:** Low. This attack would require physical access to the incubator or its hardware, making it significantly more difficult than software-based attacks.

**Impact:** Critical. Disabling sensors, alarms, communication, or other safety components could prevent the incubator from maintaining a safe environment or detecting hazardous conditions, creating a direct risk to patient safety.

**Risk:** A low likelihood combined with a critical impact results in a **Medium** risk. We agree with this risk rating because physical access presents a significant barrier to an attacker, but successful exploitation could have life-threatening consequences.

### Threat 7 – Temperature Readings Tampered

**Likelihood:** Medium. An attacker would need to gain access to the client, network traffic, or auth token to modify the temperature readings. Since the application uses network communication and relies on accurate temperature data for monitoring, this threat is very possible.

**Impact:** Critical. Tampered temperature readings could cause monitors or automated components to falsely believe the incubator is operating within safety parameters. Incorrect temperature information could result in undesired functionality placing the infant at risk.

**Risk:** A medium likelihood combined with a critical impact results in a **High** risk. We agree with this risk rating because the attacker needs some level of access, but the consequences of incorrect temperature readings could directly affect patient safety.

### Threat 8 – Audit/Accountability Failure

**Likelihood:** Medium. This threat is realistic if the system fails to accurately record authentication attempts, configuration changes, or processes. Without continuing, accurate logging, activity may not be traceable. This is especially important following an incident.

**Impact:** High. If the system does not maintain reliable logging, it will be difficult to allign actions with identity and when a given action occured. This would delay investigation efforts, recovery, and risk resiliancy.

**Risk:** A medium likelihood combined with a high impact results in a **Medium** risk. We agree with this risk rating because audit failure may not directly change the incubator environment by itself, but it nonetheless compromises integrety and accountability.
