import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { PrismaService } from './prisma/prisma.service';
import { AuteurModule } from './modules/auteur/auteur.module';
import { MaisonEditionModule } from './modules/maison-edition/maison-edition.module';
import { AuthModule } from './modules/auth/auth.module';

@Module({
  imports: [AuthModule, AuteurModule, MaisonEditionModule,],
  controllers: [AppController],
  providers: [AppService, PrismaService],
  exports: [PrismaService],
})
export class AppModule {}
