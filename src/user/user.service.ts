import { Injectable } from '@nestjs/common';
import { User } from './user.entity';
import { Model } from 'mongoose';
import { InjectConnection, InjectModel } from '@nestjs/mongoose';
import { Connection } from 'mongoose';

@Injectable()
export class UserService {
  constructor(
    @InjectConnection() private connection: Connection,
    @InjectModel(User.name) private userModel: Model<User>,
  ) {}

  async findByEmail(email: string) {
    return this.userModel.findOne({ email }).lean();
  }

  async create(input: Partial<User>) {
    return this.userModel.create(input);
  }

  async updateRefreshToken(refreshToken: string, userId: string) {
    return this.userModel.updateOne({ _id: userId }, { refreshToken });
  }
}
