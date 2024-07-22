import {
  Body,
  Controller,
  Post,
  Get,
  UseGuards,
  UseInterceptors,
  HttpException,
  Request,
  Req,
  Res,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterRequest } from './dto/register.dto';
import { TransformInterceptor } from '../interceptors/transform.interceptor';
import { LocalAuthGuard } from './guards/local-auth.guard';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { RtAuthGuard } from './guards/rt-auth.guard';
import { Response, Request as ExpressRequest } from 'express';

@Controller('auth')
@UseInterceptors(TransformInterceptor)
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  @UseGuards(LocalAuthGuard)
  async login(
    @Req() request,
    @Res({
      passthrough: true,
    })
    response: Response,
  ) {
    const user = request.user;
    const tokens = await this.authService.login(user);
    if (!tokens) throw new HttpException('Invalid email or password', 402);
    response.cookie('refreshToken', tokens.refreshToken, {
      signed: true,
      httpOnly: true,
      expires: new Date(Date.now() + 1000 * 60 * 60 * 24 * 1),
    });
    return {
      message: 'Login successful',
      data: {
        accessToken: tokens.accessToken,
      },
    };
  }

  @Post('register')
  async register(@Body() request: RegisterRequest) {
    const { email, name, password, confirmPassword } = request;
    await this.authService.register({ email, name, password, confirmPassword });
    return { message: 'User created successfully' };
  }

  @Post('generate-token')
  @UseGuards(RtAuthGuard)
  async generateToken(@Req() request) {
    const user = request.user;
    const tokens = await this.authService.generateToken(user);
    return {
      message: 'Token generated successfully',
      data: {
        accessToken: tokens.accessToken,
      },
    };
  }

  @Get('current-user')
  @UseGuards(JwtAuthGuard)
  async currentUser(@Request() req) {
    return {
      message: 'User fetched successfully',
      data: req.user,
    };
  }
}
