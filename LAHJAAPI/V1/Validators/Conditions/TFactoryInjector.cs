using AutoGenerator.Notifications;
//using AutoMapper;
//using LAHJAAPI.Data;

//namespace LAHJAAPI.V1.Validators.Conditions
//{
//    public class TFactoryInjector : ITFactoryInjector
//    {
//        private readonly IMapper _mapper;
//        private readonly DataContext _context;
//        // يمكنك حقن اي طبقة
//        public TFactoryInjector(IMapper mapper, IAutoNotifier notifier, DataContext context) : base(mapper, notifier)
//        {
//            _mapper = mapper;
//            _context = context;
//        }

//        public IMapper Mapper => _mapper;
//        public DataContext Context => _context;


//    }
//}

using AutoGenerator;
using AutoGenerator.Conditions;
using AutoGenerator.Notifications;
using AutoMapper;
using LAHJAAPI.Data;
using System;
using LAHJAAPI.V1.Validators.Conditions;
using APILAHJA.Utilities;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;

namespace ApiCore.Validators.Conditions
{
    public class TFactoryInjector : TBaseFactoryInjector, ITFactoryInjector
    {
        private readonly DataContext _context;
        private readonly IMapper _mapper;
       
        private readonly IUserClaimsHelper _userClaims;
        // يمكنك حقن اي طبقة
        public TFactoryInjector(IMapper mapper, IAutoNotifier notifier, DataContext context, IUserClaimsHelper userClaims) : base(mapper, notifier)
        {
            _context = context;
            _mapper = mapper;
            _context = context;
            _userClaims = userClaims;
        }

        public DataContext Context => _context;
        public IMapper Mapper => _mapper;
       
        public IUserClaimsHelper UserClaims => _userClaims;

        public RoleManager<IdentityRole> RoleManager => throw new NotImplementedException();
    }
}