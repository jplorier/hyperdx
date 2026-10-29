import mongoose, { Schema } from 'mongoose';

import type { ObjectId } from '.';

// Ordered least to most privileged.
export const PROXY_AUTH_ROLES = ['viewer', 'member', 'admin'] as const;
export type ProxyAuthRoleName = (typeof PROXY_AUTH_ROLES)[number];

// The role the proxy last asserted for a user. Access-key requests (API v2,
// MCP) carry no proxy headers, so they are authorized against this record.
interface IProxyAuthRole {
  _id: ObjectId;
  user: ObjectId;
  email: string;
  role: ProxyAuthRoleName;
  groups: string[];
  lastSeenAt: Date;
  createdAt: Date;
  updatedAt: Date;
}

const ProxyAuthRoleSchema = new Schema<IProxyAuthRole>(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      ref: 'User',
      unique: true,
    },
    email: { type: String, required: true },
    role: { type: String, required: true, enum: PROXY_AUTH_ROLES },
    groups: { type: [String], default: [] },
    lastSeenAt: { type: Date, required: true },
  },
  {
    timestamps: true,
  },
);

export default mongoose.model<IProxyAuthRole>(
  'ProxyAuthRole',
  ProxyAuthRoleSchema,
);
