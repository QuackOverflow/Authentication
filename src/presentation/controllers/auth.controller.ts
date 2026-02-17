import { Body, Controller, Post, Req, Res, UseGuards } from '@nestjs/common';
import { Request, Response } from 'express';
import { LoginRequest } from 'src/application/dtos/login_request';
import { AdminCreateUserRequest } from 'src/application/dtos/admin_create_user_request';
import { LoginUseCase } from 'src/application/use_cases/login.use_case';
import { LogoutUseCase } from 'src/application/use_cases/logout.use_case';
import { RefreshTokenUseCase } from 'src/application/use_cases/refresh_token.use_case';
import { AdminCreateUserUseCase } from 'src/application/use_cases/admin_create_user';
import { JwtAuthGuard } from 'src/infrastructure/guards/jwt_auth.guard';
import { RolesGuard } from 'src/infrastructure/guards/roles.guard';
import { Roles } from 'src/infrastructure/decorators/roles.decorator';
import { CreateUserUseCase } from '../../application/use_cases/create_user';
import { CreateUserRequest } from '../../application/dtos/create_user_request';
import { InvalidTokenError } from '../../domain/exceptions/auth.exceptions';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly loginUseCase: LoginUseCase,
    private readonly refreshTokenUseCase: RefreshTokenUseCase,
    private readonly createUserUseCase: CreateUserUseCase,
    private readonly logoutUseCase: LogoutUseCase,
    private readonly adminCreateUserUseCase: AdminCreateUserUseCase,
  ) {}

  @Post('login')
  async login(
    @Body() loginDto: LoginRequest,
    @Res({ passthrough: true }) response: Response,
  ) {
    const result = await this.loginUseCase.execute({
      email: loginDto.email,
      password: loginDto.password,
    });

    // Set refresh token as httpOnly cookie (only if provided)
    if (result.refreshToken) {
      response.cookie('refresh_token', result.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
        path: '/auth/refresh', // Only send to refresh endpoint
      });
    }

    if (result.accessToken) {
      response.cookie('access_token', result.accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 30 * 24 * 60 * 60 * 1000,
        path: '/',
      });
    }

    return {
      success: true,
      value: {
        accessToken: result.accessToken,
        userId: result.userId,
        expiresAt: result.expiresAt,
      },
    };
  }

  @Post('sign-up')
  async signUp(
    @Body() signUpDto: CreateUserRequest,
    @Res({ passthrough: true }) response: Response,
  ) {
    const user = await this.createUserUseCase.execute(signUpDto);
    const loginResponse = await this.loginUseCase.execute({
      email: user.email,
      password: signUpDto.password,
    });

    // Set refresh token as httpOnly cookie (only if provided)
    if (loginResponse.refreshToken) {
      response.cookie('refresh_token', loginResponse.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
        path: '/auth/refresh', // Only send to refresh endpoint
      });
    }

    if (loginResponse.accessToken) {
      response.cookie('access_token', loginResponse.accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 15 * 60 * 1000, // 15 minutes
        path: '/',
      });
    }

    return {
      success: true,
      value: {
        accessToken: loginResponse.accessToken,
        userId: loginResponse.userId,
        expiresAt: loginResponse.expiresAt,
      },
    };
  }

  @Post('refresh')
  async refreshToken(
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ) {
    const refreshToken: string = request.cookies['refresh_token'] as string;

    if (!refreshToken) {
      throw new InvalidTokenError('Refresh token not provided');
    }

    const result = await this.refreshTokenUseCase.execute({ refreshToken });

    // Set new refresh token as cookie
    response.cookie('access_token', result.accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 15 * 60 * 1000, // 15 Minutes
      path: '/',
    });

    return {
      success: true,
      value: {
        accessToken: result.accessToken,
        expiresAt: result.expiresAt,
      },
    };
  }

  @Post('logout')
  @UseGuards(JwtAuthGuard)
  async logout(
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ) {
    const refreshToken = request.cookies['refresh_token'] as string;

    await this.logoutUseCase.execute({
      refreshToken,
    });

    response.clearCookie('refresh_token', { path: '/auth/refresh' });
    response.clearCookie('access_token', { path: '/' });

    return {
      success: true,
      value: { message: 'Successfully logged out' },
    };
  }

  @Post('users')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('ADMIN')
  async createUser(@Body() dto: AdminCreateUserRequest) {
    const user = await this.adminCreateUserUseCase.execute(dto);

    return {
      id: user.id,
      name: user.name,
      email: user.email,
    };
  }
}
