import { randomUUID } from 'crypto';
import { Inject, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { ICryptoGateway } from 'src/application/interfaces/crypto_gateway';
import { ITokenGateway } from 'src/application/interfaces/token_gateway';
import {
  InvalidTokenError,
  TokenExpiredError,
} from 'src/domain/exceptions/auth.exceptions';
import { JwtPayload } from 'src/domain/value_objects/jwt_payload';

@Injectable()
export class JwtTokenGateway implements ITokenGateway {
  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    @Inject('CryptoGateway')
    private readonly cryptoGateway: ICryptoGateway,
  ) {}

  async generateAccessToken(payload: JwtPayload): Promise<string> {
    return this.jwtService.signAsync(payload.toPlainObject(), {
      secret: this.configService.get('JWT_ACCESS_SECRET'),
      issuer: this.configService.get('JWT_ISSUER', 'auth-service'),
    });
  }

  async generateRefreshToken(
    userId: string,
  ): Promise<{ token: string; tokenHash: string; expiresAt: Date }> {
    const payload = {
      sub: userId,
      type: 'refresh',
      jti: randomUUID(),
    };

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 30); // 30 days

    const token = await this.jwtService.signAsync(payload, {
      secret: this.configService.get('JWT_REFRESH_SECRET'),
    });

    // Hash the token for storage
    const tokenHash = await this.cryptoGateway.hash(token);

    return { token, tokenHash, expiresAt };
  }

  async verifyAccessToken(token: string): Promise<JwtPayload> {
    try {
      const payload: Record<string, any> = await this.jwtService.verifyAsync(
        token,
        {
          secret: this.configService.get('JWT_ACCESS_SECRET'),
        },
      );

      return JwtPayload.fromPlainObject(payload);
    } catch (error) {
      if (error instanceof TokenExpiredError) {
        throw new TokenExpiredError();
      }
      throw new InvalidTokenError();
    }
  }

  async verifyRefreshToken(
    token: string,
  ): Promise<{ userId: string; token: string }> {
    try {
      const payload: Record<string, any> = await this.jwtService.verifyAsync(
        token,
        {
          secret: this.configService.get('JWT_REFRESH_SECRET'),
        },
      );

      if (payload.type !== 'refresh') {
        throw new InvalidTokenError('Not a refresh token');
      }

      return {
        userId: payload.sub as string,
        token,
      };
    } catch (error) {
      if (error instanceof TokenExpiredError) {
        throw new TokenExpiredError();
      }
      throw new InvalidTokenError();
    }
  }
}
