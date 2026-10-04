import { describe, expect, it } from 'vitest';

import { formValuesToWirePayload, rawOutboundToFormValues } from '@/lib/xray/outbound-form-adapter';
import { outboundProtocolLabel } from '@/pages/xray/outbounds/outbounds-tab-helpers';

const raw = {
  tag: 'tuic-1',
  protocol: 'singbox',
  settings: { outbound: { type: 'tuic', server: 'a.example', server_port: 443 } },
};

describe('singbox pseudo-outbound', () => {
  it('round-trips through the form adapter unchanged', () => {
    const wire = formValuesToWirePayload(rawOutboundToFormValues(raw));
    expect(wire).toEqual(raw);
  });

  it('shows the inner sing-box type as the protocol label', () => {
    expect(outboundProtocolLabel(raw)).toBe('tuic');
    expect(outboundProtocolLabel({ protocol: 'vless' })).toBe('vless');
  });

  it('keeps the fragment dialerProxy sockopt on wire payload', () => {
    const values = rawOutboundToFormValues({
      tag: 't',
      protocol: 'trojan',
      settings: { servers: [{ address: 'h', port: 443, password: 'p' }] },
      streamSettings: {
        network: 'tcp',
        security: 'none',
        sockopt: { dialerProxy: 'jasem-fragment' },
      },
    });
    const wire = formValuesToWirePayload(values) as {
      streamSettings?: { sockopt?: { dialerProxy?: string } };
    };
    expect(wire.streamSettings?.sockopt?.dialerProxy).toBe('jasem-fragment');
  });
});
