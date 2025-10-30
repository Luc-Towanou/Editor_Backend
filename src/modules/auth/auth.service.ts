import { Injectable, BadRequestException, UnauthorizedException, ForbiddenException, NotFoundException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../../prisma/prisma.service'; // adapte si emplacement différent
import { MailerService } from './mailer/mailer.service';
import * as bcrypt from 'bcryptjs';
import { createRefreshTokenPlain, parseTTL } from './utils/tokens.util';
import { TokenPair } from './interfaces/token-pair.interface';
import { v4 as uuidv4 } from 'uuid';
import { ConfigService } from '@nestjs/config';
import dayjs from 'dayjs';
import type { StringValue } from 'ms';  //for methode sign in access token
import * as crypto from 'crypto';
import * as nodemailer from 'nodemailer';
import { JwtPayload } from 'jsonwebtoken';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private config: ConfigService,
    private mailerService: MailerService,
  ) {}

  /** --- Hashing utilities --- */
  private async hashPassword(password: string) {
    const salt = await bcrypt.genSalt(12);
    return bcrypt.hash(password, salt);
  }
  private async comparePassword(password: string, hash: string) {
    return bcrypt.compare(password, hash);
  }
  private async hashToken(token: string) {
    // on peut utiliser bcrypt pour hash (lent mais ok pour security)
    const salt = await bcrypt.genSalt(12);
    return bcrypt.hash(token, salt);
  }
  private async verifyTokenHash(token: string, hash: string) {
    return bcrypt.compare(token, hash);
  }

  /** --- Email transport basic (nodemailer) --- */
  private getTransport() {
    return nodemailer.createTransport({
      host: this.config.get('SMTP_HOST'),
      port: Number(this.config.get('SMTP_PORT') || 587),
      secure: false,
      auth: {
        user: this.config.get('SMTP_USER'),
        pass: this.config.get('SMTP_PASS'),
      },
    });
  }

  // /** --- Signup: create user + email verification OTP --- */
  // async signup(data: { // 1 la donnée de la requette pssée lors de l'inscription  
  //   nom: string;
  //   email: string;
  //   mot_de_passe: string;
  //   telephone?: string;
  //   role?: string;
  //   maison_id?: string;
  // }) {
  //   // 2- check existence user
  //   const existing = await this.prisma.user.findUnique({ where: { email: data.email }});
  //   if (existing) throw new BadRequestException('Email déjà utilisé');

  //   const hashed = await this.hashPassword(data.mot_de_passe);
  //   const user = await this.prisma.user.create({
  //     data: {
  //       nom: data.nom,
  //       email: data.email,
  //       mot_de_passe: hashed,
  //       telephone: data.telephone ?? null,
  //       role: (data.role as any) ?? 'auteur',
  //       statut: 'en_attente', // en attente de verification
  //     },
  //   });

  //   // 3- créer OTP
  //   const codePlain = Math.floor(100000 + Math.random() * 900000).toString(); // 6 digits
  //   const codeHash = await this.hashToken(codePlain);
  //   const expiresAt = dayjs().add(10, 'minute').toDate();

  //   // 4- créer le user dans la table de verifictionde mail
  //   await this.prisma.emailVerification.create({
  //     data: {
  //       user_id: user.id,
  //       codeHash,
  //       expiresAt,
  //     },
  //   });

  //   // 4- envoyer mail (simple)
  //   // const transport = this.getTransport();
  //   // await transport.sendMail({
  //   //   to: user.email,
  //   //   from: this.config.get('SMTP_FROM') || this.config.get('SMTP_USER'),
  //   //   subject: 'Vérification de votre adresse email',
  //   //   text: `Votre code de vérification : ${codePlain} (valable 10 minutes)`,
  //   //   html: `<p>Votre code de vérification : <b>${codePlain}</b> (valable 10 minutes)</p>`,
  //   // });
  //   await this.mailerService.sendMail(
  //     user.email,
  //     'Vérification de votre adresse email',
  //     `<p>Votre code de vérification : <b>${codePlain}</b> (valable 10 minutes)</p>`,
  //     // `Votre code de vérification : ${codePlain} (valable 10 minutes)`
  //   );

  //   return { userId: user.id, message: 'Compte créé. Vérifie ton email pour activer.' };
  // }
  async signup(data: {
    nom: string;
    email: string;
    mot_de_passe: string;
    telephone?: string;
    role?: string;
    maison_id?: string;
  }) {
    const existing = await this.prisma.user.findUnique({ where: { email: data.email }});
    if (existing) throw new BadRequestException('Email déjà utilisé');

    const hashed = await this.hashPassword(data.mot_de_passe);
    const codePlain = Math.floor(100000 + Math.random() * 900000).toString();
    const codeHash = await this.hashToken(codePlain);
    const expiresAt = dayjs().add(10, 'minute').toDate();

    // 👉 Transaction
    const [user] = await this.prisma.$transaction([
      this.prisma.user.create({
        data: {
          nom: data.nom,
          email: data.email,
          mot_de_passe: hashed,
          telephone: data.telephone ?? null,
          role: (data.role as any) ?? 'auteur',
          statut: 'en_attente',
        },
      }),
      // la création du code se fait dans la même transaction
      this.prisma.emailVerification.create({
        data: {
          user: { connect: { email: data.email } },
          codeHash,
          expiresAt,
        },
      }),
    ]);

    try {
      // Envoi mail
      await this.mailerService.sendMail(
        user.email,
        'Vérification de votre adresse email',
        `<p>Votre code de vérification : <b>${codePlain}</b> (valable 10 minutes)</p>`
      );
    } catch (err) {
      console.error('Erreur envoi mail:', err.message);

      // rollback manuel si le mail n’est pas parti
      
      await this.prisma.emailVerification.deleteMany({ where: { user_id: user.id } });
      await this.prisma.user.delete({ where: { id: user.id } });

      throw new BadRequestException('Erreur lors de l’envoi du mail, réessaie plus tard.');
    }

    return {
      userId: user.id,
      message: 'Compte créé. Vérifie ton email pour activer ton compte.',
    };
  }


  /** --- Verify email OTP --- */
  async verifyEmail(user_id: string, code: string) {// // 1 la donnée de la requette pssée lors de la verifiction de mail 
    
    // 2- rechercher le user  à vérifier dans la teble de verification de mail
    const record = await this.prisma.emailVerification.findFirst({
      where: { user_id, used: false },
      orderBy: { createdAt: 'desc' },
    });

    //3- verifications 
    if (!record) throw new BadRequestException('Code invalide ou expiré'); // si le user n'existe pas dans la table renvoyer une erreur 

    if (dayjs().isAfter(record.expiresAt)) throw new BadRequestException('Code expiré'); // si l'heure de la date d'expiration est dépassé, renvoyer une erreur

    const ok = await this.verifyTokenHash(code, record.codeHash);  // comprarer les code et recuperer le resultat dans 'ok'
    if (!ok) throw new BadRequestException('Code invalide');  // si le code n'est pas conforme à celui généré, renvoyer une erreur (verification est hachés)

    // 4- mark used and activate user
    await this.prisma.emailVerification.update({ where: { id: record.id }, data: { used: true }});  // marquer le user verifié dans la table de verification des mails
    await this.prisma.user.update({ where: { id: user_id }, data: { statut: 'actif' }}); // passer le user à statut : actif

    return { ok: true }; 
  }

  /** --- Validate credentials (used by LocalStrategy) --- */
  async validateUser(email: string, mot_de_passe: string) {
    const user = await this.prisma.user.findUnique({ where: { email }});
    if (!user) return null;
    const ok = await this.comparePassword(mot_de_passe, user.mot_de_passe);
    if (!ok) return null;
    if (user.statut !== 'actif') {
      // not allowed to login
      return null;
    }
    return user;
  }

  /** --- Generate token pair, store refresh hash in AuthSession --- */
  async generateTokenPair(user: any, deviceInfo?: string, ip?: string): Promise<TokenPair> {
    // payload includes maison_id if present (if user linked to auteur->maison)
    // attempt to fetch user's maison id if exists
    // let maison_id = null;
    let maison_id: string | null = null;
    try {
      const auteur = await this.prisma.auteur.findUnique({ where: { user_id: user.id } });
      maison_id = auteur?.maison_id ?? null;
    } catch (e) {
      maison_id = null;
    }

    const payload = {
      sub: user.id,
      email: user.email,
      role: user.role,
      maison_id,
    };

    const accessTtl = this.config.get<string>('ACCESS_TOKEN_TTL') || '15m';
    const accessExpiresInSec = parseInt(this.config.get('ACCESS_TOKEN_TTL_SECONDS') || '900', 10);
    // sign access token
    const accessToken = this.jwtService.sign(payload, {
      secret: this.config.get<string>('JWT_ACCESS_SECRET')!,
      expiresIn: accessTtl as StringValue, //, 
    });

    // create refresh token opaque
    const refreshPlain = createRefreshTokenPlain();
    const refreshHash = await this.hashToken(refreshPlain);

    // expiry date for refresh
    const refreshTtl = this.config.get<string>('REFRESH_TOKEN_TTL') || '30d';
    const refreshExpiresAt = dayjs().add(30, 'day').toDate(); // simple; prefer parseTTL for config

    // store session
    await this.prisma.authSession.create({
      data: {
        user_id: user.id,
        refreshHash,
        deviceInfo,
        ip,
        expiresAt: refreshExpiresAt,
      },
    });

    return {
      accessToken,
      refreshToken: refreshPlain,
      accessTokenExpiresIn: accessExpiresInSec || 900,
      refreshTokenExpiresAt: refreshExpiresAt,
    };
  }

  /** --- login flow returns tokens and stores session --- */
  async login(user: any, deviceInfo?: string, ip?: string) {
    return this.generateTokenPair(user, deviceInfo, ip);
  }

  /** --- Refresh flow with rotation --- */
  async refresh(refreshTokenPlain: string, ip?: string, deviceInfo?: string): Promise<TokenPair> {
    // find session by comparing hash
    const sessions = await this.prisma.authSession.findMany({
      where: { revoked: false, expiresAt: { gt: new Date() } },
    });

    // naive search: find matching hash
    // IMPORTANT: for performance you may want to store part of the token or userId in the refresh token string.
    // let matched = null;
    let matched: any = null;
    for (const s of sessions) {
      const ok = await this.verifyTokenHash(refreshTokenPlain, s.refreshHash);
      if (ok) {
        matched = s;
        break;
      }
    }
    if (!matched) {
      // possible token reuse or invalid token
      throw new UnauthorizedException('Refresh token invalide');
    }

    // rotate: revoke old session and create a new one
    await this.prisma.authSession.update({ where: { id: matched.id }, data: { revoked: true }});

    const user = await this.prisma.user.findUnique({ where: { id: matched.userId }});
    if (!user) throw new UnauthorizedException('Utilisateur introuvable');

    return this.generateTokenPair(user, deviceInfo, ip);
  }

  /** --- Logout: revoke session by refresh token */ 
  async logout(refreshTokenPlain: string) {
    // find and revoke
    const sessions = await this.prisma.authSession.findMany({
      where: { revoked: false },
    });
    for (const s of sessions) {
      const ok = await this.verifyTokenHash(refreshTokenPlain, s.refreshHash);
      if (ok) {
        await this.prisma.authSession.update({ where: { id: s.id }, data: { revoked: true }});
        return { ok: true };
      }
    }
    return { ok: false };
  }

  /** --- Request password reset (email) --- */
  async requestPasswordReset(email: string) {
    const user = await this.prisma.user.findUnique({ where: { email }});
    if (!user) throw new NotFoundException('Utilisateur non trouvé');

    const tokenPlain = uuidv4();
    const tokenHash = await this.hashToken(tokenPlain);
    const expiresAt = dayjs().add(60, 'minute').toDate();

    await this.prisma.passwordReset.create({
      data: { user_id: user.id, tokenHash, expiresAt },
    });

    // send email
    const transport = this.getTransport();
    await transport.sendMail({
      to: user.email,
      from: this.config.get('SMTP_FROM') || this.config.get('SMTP_USER'),
      subject: 'Réinitialisation de mot de passe',
      text: `Utilise ce token pour réinitialiser ton mot de passe : ${tokenPlain} (valable 60 min)`,
    });

    return { ok: true };
  }

  /** --- Reset password with token --- */
  async resetPassword(tokenPlain: string, newPassword: string) {
    // find record
    const records = await this.prisma.passwordReset.findMany({ where: { used: false }});
    // let matched = null;
    let matched: any = null;
    for (const r of records) {
      const ok = await this.verifyTokenHash(tokenPlain, r.tokenHash);
      if (ok) {
        matched = r;
        break;
      }
    }
    if (!matched) throw new BadRequestException('Token invalide');

    if (dayjs().isAfter(matched.expiresAt)) throw new BadRequestException('Token expiré');

    // update password
    const hashed = await this.hashPassword(newPassword);
    await this.prisma.user.update({ where: { id: matched.userId }, data: { mot_de_passe: hashed }});

    // mark token used
    await this.prisma.passwordReset.update({ where: { id: matched.id }, data: { used: true }});

    // revoke all sessions for security
    await this.prisma.authSession.updateMany({ where: { user_id: matched.userId }, data: { revoked: true }});

    return { ok: true };
  }

  /** --- helper: get current sessions for user --- */
  async getSessionsForUser(user_id: string) {
    return this.prisma.authSession.findMany({ where: { user_id }});
  }

}
