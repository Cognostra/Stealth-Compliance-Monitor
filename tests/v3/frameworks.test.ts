/**
 * Compliance Frameworks Unit Tests
 */

import {
    complianceFrameworks,
    getControlsForFinding,
    getFindingsForControl,
    soc2Framework,
    gdprFramework,
    hipaaFramework,
    findingToControlMap,
} from '../../src/v3/compliance/frameworks.js';

describe('Compliance Frameworks', () => {
    describe('Framework definitions', () => {
        it('should export SOC2 framework', () => {
            expect(soc2Framework.id).toBe('soc2');
            expect(soc2Framework.name).toBe('SOC 2 Type II');
            expect(Object.keys(soc2Framework.controls).length).toBeGreaterThan(0);
        });

        it('should export GDPR framework', () => {
            expect(gdprFramework.id).toBe('gdpr');
            expect(gdprFramework.name).toBe('GDPR');
            expect(Object.keys(gdprFramework.controls).length).toBeGreaterThan(0);
        });

        it('should export HIPAA framework', () => {
            expect(hipaaFramework.id).toBe('hipaa');
            expect(hipaaFramework.name).toBe('HIPAA Security Rule');
            expect(Object.keys(hipaaFramework.controls).length).toBeGreaterThan(0);
        });

        it('should include all three in complianceFrameworks object', () => {
            expect(complianceFrameworks.soc2).toBe(soc2Framework);
            expect(complianceFrameworks.gdpr).toBe(gdprFramework);
            expect(complianceFrameworks.hipaa).toBe(hipaaFramework);
        });
    });

    describe('SOC2 Controls', () => {
        it('should have CC6.1 for access controls', () => {
            const control = soc2Framework.controls['CC6.1'];
            expect(control.id).toBe('CC6.1');
            expect(control.title).toContain('Access');
            expect(control.checks).toContain('auth-bypass');
            expect(control.checks).toContain('idor');
        });

        it('should have CC6.6 for vulnerability management', () => {
            const control = soc2Framework.controls['CC6.6'];
            expect(control.id).toBe('CC6.6');
            expect(control.checks).toContain('xss');
            expect(control.checks).toContain('sqli');
            expect(control.checks).toContain('vulnerable-library');
        });

        it('should have CC6.7 for transmission protection', () => {
            const control = soc2Framework.controls['CC6.7'];
            expect(control.checks).toContain('missing-hsts');
            expect(control.checks).toContain('insecure-cookie');
        });
    });

    describe('GDPR Controls', () => {
        it('should have Art32 for security of processing', () => {
            const control = gdprFramework.controls['Art32'];
            expect(control.id).toBe('Art32');
            expect(control.checks).toContain('pii-exposure');
            expect(control.checks).toContain('xss');
        });

        it('should have Art25 for data protection by design', () => {
            const control = gdprFramework.controls['Art25'];
            expect(control.checks).toContain('secrets-leak');
        });
    });

    describe('HIPAA Controls', () => {
        it('should have 164.312(a) for access control', () => {
            const control = hipaaFramework.controls['164.312(a)'];
            expect(control.category).toBe('Technical Safeguards');
            expect(control.checks).toContain('auth-bypass');
        });

        it('should have 164.312(e) for transmission security', () => {
            const control = hipaaFramework.controls['164.312(e)'];
            expect(control.checks).toContain('missing-hsts');
            expect(control.checks).toContain('weak-tls');
        });
    });

    describe('getControlsForFinding()', () => {
        it('should return empty array for unknown finding', () => {
            const controls = getControlsForFinding('unknown-finding-type');
            expect(controls).toEqual([]);
        });

        it('should return controls for auth-bypass', () => {
            const controls = getControlsForFinding('auth-bypass');
            expect(controls.length).toBeGreaterThan(0);

            const soc2Controls = controls.filter((c) => c.framework === 'soc2');
            expect(soc2Controls.some((c) => c.controlId === 'CC6.1')).toBe(true);
        });

        it('should return controls across multiple frameworks for xss', () => {
            const controls = getControlsForFinding('xss');
            const frameworks = new Set(controls.map((c) => c.framework));

            expect(frameworks.has('soc2')).toBe(true);
            expect(frameworks.has('gdpr')).toBe(true);
            expect(frameworks.has('hipaa')).toBe(true);
        });

        it('should return GDPR-only controls for pii-exposure', () => {
            const controls = getControlsForFinding('pii-exposure');
            const frameworks = new Set(controls.map((c) => c.framework));

            expect(frameworks.has('gdpr')).toBe(true);
            expect(controls.some((c) => c.controlId === 'Art32')).toBe(true);
            expect(controls.some((c) => c.controlId === 'Art5')).toBe(true);
        });
    });

    describe('getFindingsForControl()', () => {
        it('should return empty array for unknown control', () => {
            const findings = getFindingsForControl('soc2', 'UNKNOWN');
            expect(findings).toEqual([]);
        });

        it('should return finding types for SOC2 CC6.1', () => {
            const findings = getFindingsForControl('soc2', 'CC6.1');
            expect(findings).toContain('auth-bypass');
            expect(findings).toContain('idor');
            expect(findings).toContain('csrf');
        });

        it('should return finding types for GDPR Art32', () => {
            const findings = getFindingsForControl('gdpr', 'Art32');
            expect(findings).toContain('pii-exposure');
            expect(findings).toContain('xss');
        });

        it('should return finding types for HIPAA 164.312(e)', () => {
            const findings = getFindingsForControl('hipaa', '164.312(e)');
            expect(findings).toContain('missing-hsts');
            expect(findings).toContain('insecure-cookie');
        });
    });

    describe('findingToControlMap', () => {
        it('should have mappings for common findings', () => {
            const findingTypes = findingToControlMap.map((m) => m.findingType);

            expect(findingTypes).toContain('auth-bypass');
            expect(findingTypes).toContain('xss');
            expect(findingTypes).toContain('sqli');
            expect(findingTypes).toContain('pii-exposure');
            expect(findingTypes).toContain('missing-hsts');
        });

        it('should have properly structured mappings', () => {
            const xssMapping = findingToControlMap.find((m) => m.findingType === 'xss');
            expect(xssMapping).toBeDefined();
            expect(xssMapping?.frameworks).toBeInstanceOf(Array);
            expect(xssMapping?.frameworks.length).toBeGreaterThan(0);

            const soc2Mapping = xssMapping?.frameworks.find((f) => f.framework === 'soc2');
            expect(soc2Mapping?.controls).toBeInstanceOf(Array);
            expect(soc2Mapping?.controls).toContain('CC6.6');
        });
    });
});
