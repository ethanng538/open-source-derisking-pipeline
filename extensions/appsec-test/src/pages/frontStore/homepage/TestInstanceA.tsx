import React from 'react';

// @ts-ignore
import { openUrl } from '@a2ui/web_core';

export interface SafeTestInstanceInterface {
  val: string;
}

export default function TestInstanceA() {
  const dependencyTrace = typeof openUrl;

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