import { Document } from 'mongoose';

export interface User extends Document {
  _id: string;
  email: string;
  name: string;
  password: string;
  refreshToken?: string;
  createdAt: Date;
  updatedAt: Date;
}
