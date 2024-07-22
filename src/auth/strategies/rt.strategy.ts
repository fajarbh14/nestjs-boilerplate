import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable } from '@nestjs/common';
import { jwtConstants } from '../constant';
import { JwtPayload } from '../interfaces/jwt-payload.interface';
@Injectable()
export class RtStrategy extends PassportStrategy(Strategy, 'rt') {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([RtStrategy.extractRefreshToken]),
      ignoreExpiration: false,
      secretOrKey: jwtConstants.secret,
    });
  }

  private static extractRefreshToken(req) {
    let token = null;
    if (req && req.signedCookies) {
      token = req.signedCookies['refreshToken'];
    }
    return token;
  }

  async validate(payload: JwtPayload) {
    return { sub: payload.sub, name: payload.name, email: payload.email };
  }
}
