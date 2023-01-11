import { Component, OnInit } from '@angular/core';
import { AuthService } from 'src/app/services/auth.service';

@Component({
  selector: 'app-nav',
  templateUrl: './nav.component.html',
  styleUrls: ['./nav.component.scss']
})
export class NavComponent implements OnInit {
  authenticated = false;
  constructor(private authService: AuthService) { }

  ngOnInit(): void {
    AuthService.authEmitter.subscribe(authenticated => {
      this.authenticated = authenticated;
    });
  }

  logout(){
    this.authService.logout().subscribe(() => {
      this.authService.accessToken = '';
      AuthService.authEmitter.emit(false);
    });
  }
}
