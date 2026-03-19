export interface ISOClause {
  id: string;
  name: string;
  description: string;
  category: string;
}

export const ISO_CLAUSES: Record<string, ISOClause> = {
  'A.8.1': {
    id: 'A.8.1',
    name: 'Policy on use of cryptographic controls',
    description: 'A policy on the use of cryptographic controls for protection of information shall be developed and implemented.',
    category: 'Cryptography',
  },
  'A.8.2': {
    id: 'A.8.2',
    name: 'Key management',
    description: 'A policy on the use, protection and lifetime of cryptographic keys shall be developed and implemented.',
    category: 'Cryptography',
  },
  'A.8.9': {
    id: 'A.8.9',
    name: 'Configuration management',
    description: 'Configurations, including security configurations, of hardware, software, services and networks shall be established, documented, implemented, monitored and reviewed.',
    category: 'Cryptography',
  },
  'A.8.10': {
    id: 'A.8.10',
    name: 'Information deletion',
    description: 'Information stored in information systems, devices or in any other storage media shall be deleted when no longer required.',
    category: 'Cryptography',
  },
  'A.5.15': {
    id: 'A.5.15',
    name: 'Access control',
    description: 'Rules to control physical and logical access to information and other associated assets shall be established and implemented.',
    category: 'Access Control',
  },
  'A.5.17': {
    id: 'A.5.17',
    name: 'Authentication information',
    description: 'Allocation and management of authentication information shall be controlled by a management process.',
    category: 'Access Control',
  },
  'A.8.3': {
    id: 'A.8.3',
    name: 'Information access restriction',
    description: 'Access to information and other associated assets shall be restricted in accordance with the established topic-specific policy on access control.',
    category: 'Access Control',
  },
  'A.8.5': {
    id: 'A.8.5',
    name: 'Secure authentication',
    description: 'Secure authentication technologies and procedures shall be established and implemented.',
    category: 'Access Control',
  },
  'A.8.20': {
    id: 'A.8.20',
    name: 'Network security',
    description: 'Networks and network devices shall be secured, managed and controlled to protect information in systems and applications.',
    category: 'Communications Security',
  },
  'A.8.21': {
    id: 'A.8.21',
    name: 'Security of network services',
    description: 'Security mechanisms, service levels and service requirements of network services shall be identified, implemented and monitored.',
    category: 'Communications Security',
  },
  'A.8.23': {
    id: 'A.8.23',
    name: 'Web filtering',
    description: 'Access to external websites shall be managed to reduce exposure to malicious content.',
    category: 'Communications Security',
  },
  'A.8.6': {
    id: 'A.8.6',
    name: 'Capacity management',
    description: 'The use of resources shall be monitored and adjusted in line with current and expected capacity requirements.',
    category: 'Operations Security',
  },
  'A.8.15': {
    id: 'A.8.15',
    name: 'Logging',
    description: 'Logs that record activities, exceptions, faults and other relevant events shall be produced, stored, protected and analysed.',
    category: 'Operations Security',
  },
  'A.8.16': {
    id: 'A.8.16',
    name: 'Monitoring activities',
    description: 'Networks, systems and applications shall be monitored for anomalous behaviour and appropriate actions taken to evaluate potential information security events.',
    category: 'Operations Security',
  },
  'A.8.7': {
    id: 'A.8.7',
    name: 'Protection against malware',
    description: 'Protection against malware shall be implemented and supported by appropriate user awareness.',
    category: 'System Security',
  },
  'A.8.8': {
    id: 'A.8.8',
    name: 'Management of technical vulnerabilities',
    description: 'Information about technical vulnerabilities of information systems in use shall be obtained, exposure to such vulnerabilities evaluated and appropriate measures taken.',
    category: 'System Security',
  },
  'A.8.12': {
    id: 'A.8.12',
    name: 'Data leakage prevention',
    description: 'Data leakage prevention measures shall be applied to systems, networks and any other devices that process, store or transmit sensitive information.',
    category: 'System Security',
  },
};

export function getClauseName(clauseId: string): string {
  return ISO_CLAUSES[clauseId]?.name ?? 'Unknown clause';
}
