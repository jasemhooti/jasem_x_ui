import { useTranslation } from 'react-i18next';
import { Collapse } from 'antd';

import type { SkippedLine } from '@/schemas/api/outbound-sub';

export default function SkippedLines({ skipped }: { skipped?: SkippedLine[] }) {
  const { t } = useTranslation();
  if (!skipped || skipped.length === 0) return null;
  return (
    <Collapse
      size="small"
      items={[
        {
          key: 'skipped',
          label: t('pages.xray.outboundSub.skippedCount', {
            count: skipped.length,
          }),
          children: (
            <ul style={{ margin: 0, paddingInlineStart: 18 }}>
              {skipped.map((s, i) => (
                <li key={i} style={{ fontSize: 12 }}>
                  <code dir="ltr" style={{ wordBreak: 'break-all' }}>
                    {s.line}
                  </code>
                  <div style={{ color: '#888' }}>{s.reason}</div>
                </li>
              ))}
            </ul>
          ),
        },
      ]}
    />
  );
}
