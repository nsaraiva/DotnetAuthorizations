﻿namespace LearningJwt.Domain.Models;

public class User
{
    public string UserName { get; set; }
    public string Password { get; set; }
    public List<string> Roles { get; set; }
}