import { Controller, Post, Body, UseGuards, Req, Res, Get, HttpCode } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignupDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';
import { VerifyEmailDto } from './dto/verify-email.dto';
import { RequestResetDto } from './dto/request-reset.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { RefreshDto } from './dto/refresh.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { Roles } from './decorators/roles.decorator';
// import { FastifyReply } from 'fastify';
import type { FastifyReply } from 'fastify';
import { ConfigService } from '@nestjs/config';

import { ApiTags, ApiBody, ApiResponse, ApiBearerAuth, ApiCreatedResponse } from '@nestjs/swagger';

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(private auth: AuthService, private config: ConfigService) {}


  @ApiCreatedResponse({ description: 'Utilisateur créé avec succès' })
  @HttpCode(200)
  @Post('signup')
  async signup(@Body() body: SignupDto) {
    return this.auth.signup(body as any);
  }

  @Post('verify-email')
  async verify(@Body() body: VerifyEmailDto) {
    return this.auth.verifyEmail(body.userId, body.code);
  }

  @HttpCode(200)
  @ApiBody({ type: LoginDto })
  @ApiResponse({ status: 200, description: 'Connexion réussie' })
  @ApiResponse({ status: 401, description: 'Identifiants invalides' })
  @Post('login')
  @HttpCode(200)
  async login(@Body() body: LoginDto, @Req() req: any, @Res({ passthrough: true }) reply: FastifyReply) {
    const user = await this.auth.validateUser(body.email, body.mot_de_passe);
    if (!user) throw { statusCode: 401, message: 'Invalid credentials' };
    const deviceInfo = body.deviceInfo ?? req.headers['user-agent'];
    const ip = req.ip || req.headers['x-forwarded-for'] || null;
    const tokens = await this.auth.login(user, deviceInfo, ip);

    // set refresh token as HttpOnly cookie
    const cookieOpts: any = {
      httpOnly: true,
      path: '/',
      domain: this.config.get('COOKIE_DOMAIN') || undefined,
      maxAge: Math.floor((tokens.refreshTokenExpiresAt.getTime() - Date.now()) / 1000),
      secure: this.config.get('NODE_ENV') === 'production',
      sameSite: 'lax',
    };
    reply.setCookie('refresh_token', tokens.refreshToken, cookieOpts);

    return { accessToken: tokens.accessToken, expiresIn: tokens.accessTokenExpiresIn };
  }

  @Post('refresh')
  @HttpCode(200)
  async refresh(@Body() body: RefreshDto, @Req() req: any, @Res({ passthrough: true }) reply: FastifyReply) {
    // prefer cookie
    const cookieToken = req.cookies?.refresh_token;
    const rt = body.refreshToken ?? cookieToken;
    if (!rt) throw { statusCode: 400, message: 'Refresh token manquant' };
    const deviceInfo = req.headers['user-agent'];
    const ip = req.ip || req.headers['x-forwarded-for'] || null;
    const tokens = await this.auth.refresh(rt, ip, deviceInfo);

    // set new refresh token cookie (rotation)
    const cookieOpts: any = {
      httpOnly: true,
      path: '/',
      domain: this.config.get('COOKIE_DOMAIN') || undefined,
      maxAge: Math.floor((tokens.refreshTokenExpiresAt.getTime() - Date.now()) / 1000),
      secure: this.config.get('NODE_ENV') === 'production',
      sameSite: 'lax',
    };
    reply.setCookie('refresh_token', tokens.refreshToken, cookieOpts);

    return { accessToken: tokens.accessToken, expiresIn: tokens.accessTokenExpiresIn };
  }

  @Post('logout')
  async logout(@Req() req: any, @Res({ passthrough: true }) reply: FastifyReply) {
    const cookieToken = req.cookies?.refresh_token;
    if (cookieToken) {
      await this.auth.logout(cookieToken);
      reply.clearCookie('refresh_token', { path: '/' });
    }
    return { ok: true };
  }

  @Post('request-reset')
  async requestReset(@Body() body: RequestResetDto) {
    return this.auth.requestPasswordReset(body.email);
  }

  @Post('reset')
  async reset(@Body() body: ResetPasswordDto) {
    return this.auth.resetPassword(body.token, body.newPassword);
  }

  @UseGuards(JwtAuthGuard)
  @Get('me')
  @ApiBearerAuth()
  @ApiResponse({ status: 200, description: 'Retourne le profil utilisateur' })
  @Get('me')
  async me(@Req() req: any) {
    // req.user fourni par JwtStrategy validate
    const user = await this.auth['prisma'].user.findUnique({ where: { id: req.user.id }});
    return { user };
  }
}
