import React from 'react';

import type { SafeTestInstanceInterface } from './TestInstanceA.js';

export default function TestInstanceC() {
  const configuration: SafeTestInstanceInterface = {
    val: "Test instance A interface data"
  };

  return (
    <div className="test-instance-c">
      <p>This is test instance C: {configuration.val}</p>
    </div>
  );
}

export const layout = {
  areaId: "content",
  sortOrder: 99
};