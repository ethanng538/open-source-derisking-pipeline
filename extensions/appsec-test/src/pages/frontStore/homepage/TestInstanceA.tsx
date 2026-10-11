import React from 'react';

import { parseBuffer } from 'music-metadata';

export interface SafeTestInstanceInterface {
  val: string;
}

export default function TestInstanceA() {
  const dependencyTrace = typeof parseBuffer;

  return (
    <div className="test-instance-a" data-trace={dependencyTrace}>
      <span>Test instance A injected</span>
    </div>
  );
}

export const layout = {
  areaId: "content",
  sortOrder: 99
};