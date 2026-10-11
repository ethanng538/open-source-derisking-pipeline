import React from 'react';
import DOMPurify from 'dompurify';

export interface SafeTestInstanceInterface {
  val: string;
}

export default function TestInstanceA() {
  const dependencyTrace = typeof DOMPurify.sanitize;

  return (
    <div className="test-instance-d" data-trace={dependencyTrace}>
      <span>Test instance D injected</span>
    </div>
  );
}

export const layout = {
  areaId: "content",
  sortOrder: 99
};