import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';

@Module({
  imports: [
    MongooseModule.forRoot(
      'mongodb+srv://fajarvuana:BpZ3gR5OTg7WwX7E@socialab.v2wjcsi.mongodb.net/account?retryWrites=true&w=majority',
    ),
  ],
})
export class DatabaseModule {}
