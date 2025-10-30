import { Injectable } from '@nestjs/common';
import sgMail from '@sendgrid/mail';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class MailerService {
  constructor(private config: ConfigService) {
    const apiKey = this.config.get<string>('SENDGRID_API_KEY');
    if (!apiKey) {
    throw new Error('SENDGRID_API_KEY is missing in environment variables');
    }
    sgMail.setApiKey(apiKey);
    // sgMail.setApiKey(this.config.get<string>('SENDGRID_API_KEY'));
  }

  

  async sendMail(to: string, subject: string, html: string) {
    const msg = {
      to,
      from: this.config.get('MAIL_FROM') || 'towanouluc@gmail.com',  //
      subject,
      html,
    };
    try {
      await sgMail.send(msg);
      return { success: true };
    } catch (error) {
      console.error('Erreur SendGrid:', error);
      throw new Error('Erreur envoi email');
    }
  }
}
