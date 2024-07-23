import { HttpException, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { UserService } from 'src/user/user.service';
import { LoginRequest } from './dto/login.dto';
import { RegisterRequest } from './dto/register.dto';
import { User } from '../user/interfaces/user.interface';
@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UserService,
    private readonly jwtService: JwtService,
  ) {}

  async register(input: RegisterRequest) {
    const user = await this.userService.findByEmail(input.email);
    if (user) {
      throw new HttpException('User already exists', 409);
    }

    if (input.password !== input.confirmPassword) {
      throw new HttpException('Passwords do not match', 400);
    }

    const hashedPassword = await bcrypt.hash(input.password, 10);

    return this.userService.create({
      email: input.email,
      name: input.name,
      password: hashedPassword,
    });
  }

  async validateUser({ email, password }: LoginRequest) {
    const user = await this.userService.findByEmail(email);

    if (!user) throw new HttpException('Invalid email or password', 401);

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (user && isPasswordValid) {
      const { password, ...result } = user;
      return result;
    }
    return null;
  }

  async login(user: User) {
    const accessToken = await this.generateAccessToken(user);

    const refreshToken = this.jwtService.sign(user, { expiresIn: '1d' });
    await this.updateRefreshToken(refreshToken, user._id);

    return {
      accessToken: accessToken,
      refreshToken: refreshToken,
    };
  }

  async logout(userId: string) {
    if (!userId) throw new HttpException('User not found', 404);
    await this.updateRefreshToken(null, userId);
  }

  async updateRefreshToken(refreshToken: string, userId: string) {
    return this.userService.updateRefreshToken(refreshToken, userId);
  }

  async generateAccessToken(user: User) {
    const payload = { email: user.email, name: user.name, sub: user._id };
    const token = this.jwtService.sign(payload, { expiresIn: '15m' });
    return token;
  }
}
