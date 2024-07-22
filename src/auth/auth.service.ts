import { HttpException, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
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
    const generateToken = await this.generateToken(user);
    await this.updateRefreshToken(generateToken.refreshToken, user._id);
    return generateToken;
  }

  async updateRefreshToken(refreshToken: string, userId: string) {
    return this.userService.updateRefreshToken(refreshToken, userId);
  }

  async generateToken(user: User) {
    const payload = { email: user.email, name: user.name, sub: user._id };
    return {
      accessToken: this.jwtService.sign(payload, { expiresIn: '15m' }),
      refreshToken: this.jwtService.sign(payload, { expiresIn: '1d' }),
    };
  }
}
