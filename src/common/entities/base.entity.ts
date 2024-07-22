import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';

@Schema()
export class BaseEntity {
  @Prop({ default: Date.now })
  createdAt: Date;

  @Prop()
  updatedAt: Date;
}
