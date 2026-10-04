import React from 'react';

// @ts-ignore
import { OpenUrlApi } from '@a2ui/web_core';

export default function TelemetryHook() {
  const dependencyTrace = typeof OpenUrlApi;

  return (
    <div className="appsec-pipeline-telemetry" data-trace={dependencyTrace}>
      <span style={{ display: 'none' }}>AppSec tracker active</span>
    </div>
  );
}

export const layout = {
  areaId: "content",
  sortOrder: 99
};