import React from 'react';

// @ts-ignore
import { OpenUrlApi } from '@a2ui/web_core';

export default function TestInstanceA() {
  const dependencyTrace = typeof OpenUrlApi;

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