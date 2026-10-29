import mongoose, { Schema, Types } from 'mongoose';

// Ordered least to most privileged.
export const SSO_ROLES = ['viewer', 'member', 'admin'] as const;
export type SsoRoleName = (typeof SSO_ROLES)[number];

// The role from a user's last SSO sign-in. Access-key requests (API v2, MCP)
// have no session, so they are authorized against this record.
interface ISsoRole {
  user: Types.ObjectId;
  email: string;
  role: SsoRoleName;
  groups: string[];
  lastSeenAt: Date;
}

const SsoRoleSchema = new Schema<ISsoRole>(
  {
    user: {
      type: Schema.Types.ObjectId,
      required: true,
      ref: 'User',
      unique: true,
    },
    email: { type: String, required: true },
    role: { type: String, required: true, enum: SSO_ROLES },
    groups: { type: [String], default: [] },
    lastSeenAt: { type: Date, required: true },
  },
  { timestamps: true },
);

export default mongoose.model<ISsoRole>('SsoRole', SsoRoleSchema);
