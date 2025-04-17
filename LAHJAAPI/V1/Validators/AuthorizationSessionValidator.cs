 
using AutoGenerator.Conditions;
using FluentResults;
using LAHJAAPI.Data;
using LAHJAAPI.Models;
 
using LAHJAAPI.V1.Validators;
using LAHJAAPI.V1.Validators.Conditions;
using Microsoft.AspNetCore.Mvc;
 
using V1.DyModels.Dso.Requests;
using V1.DyModels.Dso.ResponseFilters;
using V1.DyModels.VMs;

namespace ApiCore.Validators
{
    public enum SessionValidatorStates
    {
        HasSessionToken,
        HasAuthorizationType,
        HasStartTime,
        IsActive,
        HasUserId,
        HasEndTime,
        IsFull,
        IsFound,
        IsEncrypt,
        IsAllowedServiceUser
    }

    public class AuthorizationSessionValidator : BaseValidator<AuthorizationSessionResponseFilterDso, SessionValidatorStates>, ITValidator
    {
        DataContext _context;
        private readonly IConditionChecker _checker;

        public AuthorizationSessionValidator(IConditionChecker checker) : base(checker)
        {
            _context = checker.Injector.Context;
            _checker = checker;
        }

        protected override void InitializeConditions()
        {
            _provider.Register(
                SessionValidatorStates.IsFound,
                new LambdaCondition<AuthorizationSessionFilterVM>(
                    nameof(SessionValidatorStates.IsFound),
                    context => IsFound(context.Id),
                    "Session not found"
                )
            );

            _provider.Register(
                SessionValidatorStates.IsActive,
                new LambdaCondition<AuthorizationSessionFilterVM>(
                    nameof(SessionValidatorStates.IsActive),
                    context => IsActive(context.Id),
                    "Session not active"
                )
            );

            _provider.Register(
                SessionValidatorStates.HasSessionToken,
                new LambdaCondition<AuthorizationSessionRequestDso>(
                    nameof(SessionValidatorStates.HasSessionToken),
                    context => !string.IsNullOrWhiteSpace(context.SessionToken),
                    "Session Token is required"
                )
            );

            _provider.Register(
                SessionValidatorStates.HasAuthorizationType,
                new LambdaCondition<AuthorizationSessionRequestDso>(
                    nameof(SessionValidatorStates.HasAuthorizationType),
                    context => !string.IsNullOrWhiteSpace(context.AuthorizationType),
                    "Authorization Type is required"
                )
            );


            _provider.Register(
                SessionValidatorStates.HasStartTime,
                new LambdaCondition<AuthorizationSessionRequestDso>(
                    nameof(SessionValidatorStates.HasStartTime),
                    context => context.StartTime != default,
                    "Start Time is required"
                )
            );
            _provider.Register(
               SessionValidatorStates.IsAllowedServiceUser,
               new LambdaCondition<string>(
                   nameof(SessionValidatorStates.IsAllowedServiceUser),
                   context => IsAllowedServiceUser(context),
                   "Start Time is required"
               )
           );

            _provider.Register(
                SessionValidatorStates.IsActive,
                new LambdaCondition<AuthorizationSessionRequestDso>(
                    nameof(SessionValidatorStates.IsActive),
                    context => context.IsActive,
                    "Session must be active"
                )
            );

            _provider.Register(
                SessionValidatorStates.HasUserId,
                new LambdaCondition<AuthorizationSessionRequestDso>(
                    nameof(SessionValidatorStates.HasUserId),
                    context => !string.IsNullOrWhiteSpace(context.UserId),
                    "User ID is required"
                )
            );

            _provider.Register(
                SessionValidatorStates.HasEndTime,
                new LambdaCondition<AuthorizationSessionRequestDso>(
                    nameof(SessionValidatorStates.HasEndTime),
                    context => context.EndTime.HasValue,
                    "End Time is required"
                )
            );

            _provider.Register(
                SessionValidatorStates.IsFull,
                new LambdaCondition<AuthorizationSessionRequestDso>(
                    nameof(SessionValidatorStates.IsFull),
                    context => IsCreateAuthorizationSessionAsync(context),
                    "Authorization session is incomplete"
                )
            );

            _provider.Register(
                SessionValidatorStates.IsEncrypt,
                new LambdaCondition<EncryptTokenRequest>(
                    nameof(SessionValidatorStates.IsEncrypt),
                    context => IsEncryptFromWebAsync(context),
                    "Authorization session is incomplete"
                )
            );
        }
        AuthorizationSession? Session { get; set; } = null;
        private AuthorizationSession? GetSession(string? id)
        {
            if (Session is not null) return Session;
            if (id == null) id = _checker.Injector.UserClaims.SessionId;
            if (string.IsNullOrWhiteSpace(id)) return null;
            return Session = _context.AuthorizationSessions.FirstOrDefault(s => s.Id == id);
        }

        private bool IsFound(string? id)
        {
            return GetSession(id) is not null;
        }


        private bool IsActive(string? id)
        {
            if (!IsFound(id)) return false;
            var session = GetSession(id);
            return session!.IsActive;
        }

        private bool CheckCustomerId(string userId)
        {
            return _checker.Check(ApplicationUserValidatorStates.HasCustomerId, userId);
        }

        private bool CheckSessionToken(string sessionToken)
        {
            return !string.IsNullOrWhiteSpace(sessionToken);
        }

        private bool CheckAuthorizationType(string authorizationType)
        {
            return !string.IsNullOrWhiteSpace(authorizationType);
        }



        private bool IsValidAuthorizationSession(AuthorizationSessionRequestDso context)
        {
            var conditions = new List<Func<AuthorizationSessionRequestDso, bool>>
            {
                c =>CheckSessionToken(c.SessionToken),
                c =>CheckAuthorizationType(c.AuthorizationType),
                c => c.StartTime != default,
                c => CheckCustomerId(c.UserId),
                c => c.IsActive,
                c => c.EndTime.HasValue,
            };

            return conditions.All(condition => condition(context));
        }

        private async Task<ConditionResult> ValidateWebServiceIdResult(string serviceid)
        {

            var service = await _checker.CheckAndResultAsync(ServiceValidatorStates.IsServiceIdAndResult, serviceid);
            if (service.Success is true)
            {
                var objservice = (LAHJAAPI.Models.Service)service.Result;

                return new ConditionResult(true, objservice, "susfule");

            }
            return new ConditionResult(false, null, "error");
        }

        private async Task<Service> CheckServicType(string serviceid)
        {
            var result =await ValidateWebServiceIdResult(serviceid);
            if(result.Success is true)
            {
               var obj=(Service)result.Result;
                return obj;


            }
            return null;
                
        }
        private async  Task <ConditionResult> IsAllowedServiceUser(string userId)
        {



            var resultservice = await _checker.CheckAndResultAsync(
                           ServiceValidatorStates.IsAllowedServiceUser,
                            userId);

            if (resultservice.Success is true) return new ConditionResult(true, resultservice, "");
            return new ConditionResult(true,
                new ProblemDetails
                {
                    Title = "CreateAuthorizationSessionAsync",
                    Detail = "No Model allow .",
                    Status = 603
                }, ""
            ); 
       
            
           
        }

        private async Task<bool>IsPlanApi(string planid)
        {

            return true;
        }

        private async Task<ConditionResult> IsIsActiveAndResultSub(string userId)
        {

            var result = await _checker.CheckAndResultAsync(
                   SubscriptionValidatorStates.IsActiveAndResult,
                   userId
               );

            // If result is NOT successful, return failure (same in both branches currently)
            if (result.Success is false)
            {
                return new ConditionResult(false, new ProblemDetails
                {
                    Title = "CreateAuthorizationSessionAsync",
                    Detail = "No Active subscription.",
                    Status = 603
                }, "");
            }
            return new ConditionResult(true, result.Result, "");



        }
        private async Task<bool> ValidateWebSpaceId(string spaceId)
        {

            return await _checker.CheckAsync(SpaceValidatorStates.IsCountSpces, spaceId);
        }

        private async Task<ConditionResult> IsCreateAuthorizationSessionAsync(AuthorizationSessionRequestDso context)
        {
            // Validate the input session context
            if (!IsValidAuthorizationSession(context))
            {
                return new ConditionResult(false, new ProblemDetails
                {
                    Title = "Create space",
                    Detail = "No IsValidAuthorizationSession",
                    Status = 603
                }, "");

            }


            var resultsub = await IsIsActiveAndResultSub(context.UserId);
            if (resultsub.Success is false) return resultsub;

            //var service = await CheckServicType(context.ServicesIds);
            //if (service == null)
            //{
               

            //}
            //var resultser = await ValidateWebServiceIdResult(context.UserId);
            //if (resultser.Success is false) return resultser;

 


            //var resultuserser= await IsAllowedServiceUser(context.UserId);
            //if(resultuserser.Success is false)return resultuserser;

            


            return new ConditionResult(true, null, "sussful");






        }



      
        private async Task<bool> ValidateWebToken(DataTokenRequest context)
        {




            if (context == null) return false;
            return false;


        }


        async Task<ConditionResult> IsEncryptFromWebAsync(EncryptTokenRequest context)
        {
           

          
            if (context.Expires == null || context.Expires <= DateTime.UtcNow)
            {


                return new ConditionResult(false, new ProblemDetails
                {
                    Title = "IsEncryptFromWebAsync",
                    Detail = "ExpiresAt is invalid or has expired. ",
                    Status = 603

                });
               
               
            }

            if (context.SpaceId != null) 
            
            
            {

               if(! await ValidateWebSpaceId(context.SpaceId))
                {

                    return new ConditionResult(false, new ProblemDetails
                    {
                        Title = "IsEncryptFromWebAsync",
                        Detail = "You cannot create session for a space because you have reached the allowed limit. ",
                        Status = 603

                    });

                }



            }
            return new ConditionResult(true, null, "");

           

           
          
 

            
        }



      



    }
}
