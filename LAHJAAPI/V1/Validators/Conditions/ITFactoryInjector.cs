using APILAHJA.Utilities;
using AutoGenerator.Conditions;
using LAHJAAPI.Data;
using LAHJAAPI.Models;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;

namespace LAHJAAPI.V1.Validators.Conditions
{
    public interface ITFactoryInjector : ITBaseFactoryInjector
    {
        public DataContext Context { get; }
        public IUserClaimsHelper UserClaims { get; }


        public  RoleManager<IdentityRole> RoleManager { get; }

    }
}