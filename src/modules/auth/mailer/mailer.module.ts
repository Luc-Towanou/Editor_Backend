// mailer.module.ts
import { Module } from '@nestjs/common';
import { MailerService } from './mailer.service';
import { ConfigModule } from '@nestjs/config';

@Module({
  imports: [ConfigModule], // 👈 à ajouter
  providers: [MailerService],
  exports: [MailerService], // 👈 pour le rendre disponible aux autres modules
})
export class MailerModule {}
