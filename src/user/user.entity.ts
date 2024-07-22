import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument } from 'mongoose';
import { BaseEntity } from 'src/common/entities/base.entity';
export type UsertDocument = HydratedDocument<User>;

@Schema()
export class User extends BaseEntity {
  @Prop()
  email: string;

  @Prop()
  name: string;

  @Prop({ hidden: true })
  password: string;

  @Prop({ hidden: true })
  refreshToken?: string;
}

export const UserSchema = SchemaFactory.createForClass(User);
