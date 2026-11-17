import validators from './generated/wire.cjs';
import type {components as DetailComponents} from './generated/c09';
export type InventoryDetail=DetailComponents['schemas']['InventoryDetail'];
import type { components } from './generated/c03';

export type Asset=components['schemas']['Asset'];
export type AssetPage=components['schemas']['AssetPage'];
export type Source=components['schemas']['Source'];
export type SourcePage=components['schemas']['SourcePage'];
export type SourceProfile={tenant_id:string;source_id:string;source_state:string;managed:boolean;config:{profile_revision:string;heartbeat_seconds:number;inventory_seconds:number;spool_limit_bytes:number};applied_revision:string|null;last_config_contact_at:string|null;last_contact_at:string|null;last_successful_inventory_at:string|null};
export type Session=components['schemas']['Session'];
export type FactEvidence12={observation_id:string;origin:{source_id:string;source_kind:'agent'|'collector'|'portable';generation_id:string};source_sequence:string;collected_at:string;clock_quality:string};
export type RecordPage12={section:string;projection_revision:string;section_state:{status:string;clock_uncertain:boolean;last_attempt:FactEvidence12;sources?:{source_id:string;status:string;collected_at:string}[]}|null;items:{record_key:string;field:string;value:unknown;evidence:FactEvidence12}[];next_cursor:string|null};
export type TopologyNode={id:string;kind:'host'|'subnet'|'gateway';label:string;detail?:string;asset_uid?:string;router?:boolean;device?:'server'|'workstation'|'virtual_machine'|'hypervisor'|'router'|'switch'|'unknown'};
export type DeviceType='server'|'workstation'|'virtual_machine'|'hypervisor'|'switch'|'router'|'firewall'|'access_point'|'printer'|'storage'|'cloud'|'other';
export type MapPoint={x:number;y:number};
export type LinkKind='copper'|'fiber'|'wireless'|'trunk'|'vpn'|'virtual'|'logical';
export type MapDocument={positions:Record<string,MapPoint>;devices:{id:string;type:DeviceType;label:string;note?:string;address?:string;at:MapPoint}[];links:{id:string;a:string;b:string;kind:LinkKind;port_a?:string;port_b?:string;label?:string}[];groups:{id:string;label:string;color:'green'|'blue'|'amber'|'red'|'gray'|'violet';at:MapPoint;width:number;height:number}[];notes:{id:string;text:string;at:MapPoint}[];overrides:Record<string,{type?:DeviceType;label?:string;hidden?:boolean}>};
export type NetworkMap={revision:string;updated_at:string|null;updated_by:string|null;document:MapDocument};
export type TopologyLink={a:string;b:string;role?:'gateway';layer:'L2'|'L3';confidence:'confirmed'|'probable'|'weak';evidence:{source:string;detail:string;origin?:string}[];conflicts?:string[]};
export type Conflict={conflict_id:string;reason_code:string;state:'open'|'resolved'|'dismissed';revision:string;source_record_key:string;source_id:string;namespace:string;source_local_id:string;resolution_state:string;asset_uid:string|null;candidate_asset_uids:string[];pending_observations:number;observed_hostname?:string};
export type ConflictPage={tenant_id:string;state:string;items:Conflict[];next_cursor:string|null};
export type ConflictResult={conflict_id:string;action:string;asset_uid:string|null;replayed_observations:number};
export type SourceRecord={source_record_key:string;source_id:string;namespace:string;source_local_id:string;observations:number};
export type SourceRecordPage={tenant_id:string;asset_uid:string;version:string;items:SourceRecord[]};
export type AssetOperation={operation_id:string;kind:'merge'|'split';from_asset_uid:string;to_asset_uid:string;created:boolean;moved_records:number;relinked_observations:number;rebuilt_observations:number};
export type Evidence={observation_id:string;source_id:string;source_kind:'agent'|'collector'|'portable';collected_at:string;clock_quality:string};
export type AssetClassName='server'|'workstation'|'network_device'|'printer'|'virtual_machine'|'unknown';
export type CIEnd={kind:'asset'|'service';id:string};
export type Relation={relation_id:string;relation_type:'runs_on'|'uses'|'depends_on'|'hosts'|'connected_to';from:CIEnd;to:CIEnd;origin:'manual'|'observed';confidence:'confirmed'|'probable'|'weak';note:string|null;valid_from:string;valid_to:string|null;actor_ref:string};
export type RetiredAsset={asset_uid:string;display_name:string|null;observed_hostname:string|null;last_inventory_at:string|null;retired:{retired_at:string;reason:string;retired_by:string}};
export type AssetCMDB={tenant_id:string;asset_uid:string;class:{observed:AssetClassName;observed_reason:string;manual:AssetClassName|null;effective:AssetClassName};business_revision:string;software_count:number;component_count:number;relations:Relation[];retired:{retired_at:string;reason:string;retired_by:string}|null};
export type Installation={record_key:string;name:string|null;version:string|null;publisher:string|null;architecture:string|null;package_source:string|null;evidence:Evidence};
export type SoftwarePage={tenant_id:string;asset_uid:string;items:Installation[];next_cursor:string|null};
export type Component={section:'hardware'|'resources';record_key:string;kind:string|null;name:string|null;vendor:string|null;model:string|null;serial:string|null;size_bytes:string|null;evidence:Evidence};
export type ComponentList={tenant_id:string;asset_uid:string;items:Component[]};
export type Product={name:string;publisher:string|null;installations:number;assets:number;versions:string[];asset_uids:string[]};
export type ProductList={tenant_id:string;query:string;items:Product[]};
export type CIService={service_uid:string;name:string;description:string|null;criticality:'unknown'|'low'|'medium'|'high'|'critical';revision:string;created_at:string;retired_at:string|null};
export type ServicePage={tenant_id:string;items:CIService[];next_cursor:string|null};
export type ServiceDetail=CIService&{tenant_id:string;relations:Relation[]};
export type RoleName='accountable'|'business_owner'|'technical'|'custodian';
export type Subject={subject_id:string;kind:'person'|'team';name:string;contact:string;active:boolean;username:string|null;revision:string;site_fallback:boolean;members:number;origin:'local'|'ldap';synced_at:string|null;directory_login?:string};
export type SubjectPage={tenant_id:string;items:Subject[];next_cursor:string|null};
export type SubjectResult={subject:Subject;reassigned_assignments:number};
export type Assignment={role:RoleName;subject_id:string;subject_name:string;subject_kind:'person'|'team';valid_from:string;valid_to:string|null;reason_code:string;note:string|null;actor_ref:string};
export type AssetAssignments={tenant_id:string;asset_uid:string;version:string;active:Assignment[];history:Assignment[]};
export type BulkAssignResult={applied:number;unchanged:number;stale_asset_uids:string[]};
export type WorklistItem={asset_uid:string;version:string;display_name:string|null;observed_hostname:string|null;assignments:Assignment[]};
export type WorklistPage={tenant_id:string;scope:'mine'|'team'|'unassigned'|'attention';items:WorklistItem[];next_cursor:string|null};
export type SearchItem={asset_uid:string;display_name:string|null;observed_hostname:string|null;observed_os:string|null;score:number|null;fragment:string;highlights:[number,number][]};
export type SearchPage={tenant_id:string;query:string;mode:'fulltext'|'fallback_exact';notice?:string;pending_index_events:number;items:SearchItem[];facets:{os:Record<string,number>;class:Record<string,number>};next_cursor:string|null};
export type Topology={tenant_id:string;generated_at:string;nodes:TopologyNode[];links:TopologyLink[];truncated:boolean;hosts_with_network_facts:number};
export type SyncCounters={people_seen?:number;teams_seen?:number;created?:number;updated?:number;deactivated?:number;reactivated?:number;members_added?:number;members_removed?:number;logins_linked?:number;assignments_reassigned?:number;problems?:string[]};
export type SyncRun={run_id:string;mode:'full'|'incremental';started_at:string;finished_at:string;status:'succeeded'|'failed';counters:SyncCounters;error:string|null};
export type DirectorySyncStatus={tenant_id:string;configured:boolean;source:string|null;interval_minutes:number;full_sync_hours:number;teams_enabled:boolean;runs:SyncRun[]};
export type CSVRowResult={line:number;asset_uid:string;status:'applied'|'unchanged'|'stale_revision'|'not_found'|'invalid';field:string|null;business_revision:string|null};
export type CSVImportResult={tenant_id:string;dry_run:boolean;format:string;counts:Record<CSVRowResult['status'],number>;results:CSVRowResult[]};
export type WebhookEventType='asset.created.v1'|'asset.facts_changed.v1'|'responsibility.assigned.v1'|'observation.recorded.v1'|'source.contact_updated.v1'|'source.profile_updated.v1'|'ticket.created.v1'|'ticket.state_changed.v1'|'ticket.assigned.v1'|'ticket.sla_warning.v1'|'ticket.sla_breached.v1';
export type WebhookSubscription={subscription_id:string;url:string;event_types:WebhookEventType[];active:boolean;revision:string;created_at:string;pending:number;delivered:number;dead:number};
export type WebhookList={tenant_id:string;enabled:boolean;can_enable:boolean;event_types:WebhookEventType[];items:WebhookSubscription[]};
export type WebhookCreated={subscription:WebhookSubscription;signing_secret:string};
export type WebhookDelivery={event_id:string;event_type:WebhookEventType;occurred_at:string;state:'pending'|'delivered'|'dead';attempts:number;next_attempt_at:string|null;last_status:number|null;last_error:string|null;delivered_at:string|null};
export type WebhookDeliveryPage={tenant_id:string;subscription_id:string;items:WebhookDelivery[]};
export type DirectoryWebSettings={url:string;base_dn:string;bind_dn:string;user_filter?:string;group_filter?:string;guid_attribute?:string;login_attribute?:string;changed_attribute?:string;interval_minutes?:number;full_sync_hours?:number;ca_certificate_pem?:string;tls_server_name?:string};
export type DirectorySettingsView={tenant_id:string;source:'none'|'web'|'config';secrets_available:boolean;revision:string|null;settings:DirectoryWebSettings|null;password_set:boolean};
export type DirectoryTestResult={ok:boolean;people_found:number;teams_found:number;error:string|null};
export type RegistrationCode={code_id:string;source_kind:'agent'|'collector';site_id:string;collector_id:string|null;inventory_platform:'windows/amd64'|'linux/amd64'|null;max_uses:number;used:number;expires_at:string;revoked_at:string|null;comment:string;created_by:string;created_at:string;state:'active'|'exhausted'|'expired'|'revoked';code?:string;center_fingerprint?:string};
export type PortableScope={site_id:string;site_name:string;scope_id:string;namespace:string};
export type PortableReport={source_id:string;records:{observation_id:string;disposition:string;asset_id?:string;reason_code?:string}[];complete:boolean;remaining:number;encrypted:boolean};
export type PortableEncryption={key_id:string;public_key:string};
export class ApiError extends Error {
 constructor(public status:number,public code:string,public requestId?:string){super(code)}
}
const messages:Record<string,string>={INVALID_INPUT:'Проверьте введённые данные.',ASSET_MERGED:'Карточка уже объединена с другой: откройте актуальную.',INVALID_OPERATION:'Операция недоступна: проверьте выбранные записи и UID.',CONFLICT:'Состояние изменилось: обновите список.',INVALID_RESOLUTION:'Это действие недоступно для выбранного конфликта.',AUTHENTICATION_REQUIRED:'Сессия завершилась. Войдите снова.',INVALID_CREDENTIALS:'Не удалось войти. Проверьте имя и пароль.',FORBIDDEN:'Недостаточно прав для этого действия.',NOT_FOUND:'Объект не найден или недоступен.',REVISION_MISMATCH:'Карточка изменилась. Обновите данные.',RATE_LIMITED:'Слишком много запросов. Повторите немного позже.',CONTRACT_MISMATCH:'Версии интерфейса и API несовместимы. Обратитесь к администратору.',INVALID_RESPONSE:'Сервер вернул ответ неизвестного формата.',NETWORK_ERROR:'Нет связи с сервером. Проверьте соединение.',CAPABILITY_NOT_ENABLED:'Эта возможность пока недоступна.',UNIT_RESERVED:'Экземпляр зарезервирован за другим сотрудником: выдать можно только ему или после отмены резерва.',INCOMPATIBLE_COMPONENT:'Комплектующее не подходит к модели актива по каталогу.',NO_PERSON_SUBJECT:'У вашей учётной записи нет записи в оргструктуре: «взять себе» недоступно, назначьте исполнителя вручную.',LOCATION_UNDER_INVENTORY:'По этому месту идёт инвентаризация: операции недоступны до её закрытия.',WINDOW_CONFLICT:'Окно пересекается с другими изменениями на тех же активах/сервисах: подтвердите планирование явно.',NO_CHANGE_WINDOW:'Сначала задайте окно изменения: начало, конец, риск, план работ и отката.',REGISTRATION_CODE_REJECTED:'Код не принят: неверный, просрочен, отозван или исчерпан.',ALREADY_REGISTERED:'Эта машина уже зарегистрирована этим кодом.',NOT_APPROVER:'Решение по заявке принимает только назначенный согласующий (или администратор).'};
// UserError — понятное пользователю сообщение, сформированное в интерфейсе (не текст исключения)
export class UserError extends Error{}
export function errorMessage(error:unknown){if(error instanceof UserError)return error.message;return error instanceof ApiError?(messages[error.code]??'Не удалось выполнить запрос. Повторите позже.'):'Не удалось выполнить запрос. Повторите позже.'}
async function call<T>(path:string,name:string|undefined,init:RequestInit={}):Promise<T>{
 let response:Response;
 try{response=await fetch(path,{...init,credentials:'same-origin',cache:'no-store',signal:init.signal??AbortSignal.timeout(15000),headers:{Accept:'application/json',...(init.body?{'Content-Type':'application/json'}:{}),...init.headers}})}catch{throw new ApiError(0,'NETWORK_ERROR')}
 const raw=await response.text();if(raw.length>1048576)throw new ApiError(response.status,'INVALID_RESPONSE');
 let value:unknown;try{value=raw?JSON.parse(raw):undefined}catch{throw new ApiError(response.status,'INVALID_RESPONSE')}
 if(!response.ok){const error=value as {code?:string;request_id?:string}|undefined;throw new ApiError(response.status,error?.code??'REQUEST_FAILED',error?.request_id)}
 if(name){const check=validators[name];if(!check?.(value))throw new ApiError(response.status,'INVALID_RESPONSE')}
 return value as T;
}
// C51 — обследования сети (contracts/c51-discovery.schema.json)
export type DiscoveryProbe='tcp'|'arp'|'icmp';
export type DiscoveryRun={run_id:string;network_id:string;trigger:'manual'|'schedule';requested_by:string;requested_at:string;state:'queued'|'running'|'done'|'failed';finished_at:string|null;addresses:number|null;found:number|null;new_hosts:number|null;missing:number|null;errors:string[]};
export type DiscoveryNetwork={network_id:string;site_id:string;collector_id:string;name:string;cidr:string;probes:DiscoveryProbe[];schedule_minutes:number|null;active:boolean;revision:string;last_run:DiscoveryRun|null;present_hosts:number;missing_hosts:number};
export type DiscoveryNetworkPage={items:DiscoveryNetwork[];limits:{max_prefix:number;rate_per_second:number;min_schedule_minutes:number;miss_after:number;tcp_ports:number[]}};
export type DiscoveryHost={ip:string;mac:string|null;ports:number[];icmp:boolean;first_seen:string;last_seen:string;state:'present'|'missing';misses:number;missing_since:string|null;asset_uid:string|null};
export type WLocation={location_id:string;site_id:string;parent_id:string|null;kind:'warehouse'|'bin'|'repair';name:string;active:boolean};
export type WItem={item_id:string;name:string;kind:'serial'|'quantity';unit:string;category:string|null;active:boolean;compatible_models:string[]};
export type WUnit={unit_id:string;item_id:string;item_name:string;serial:string;inventory_no:string|null;asset_uid:string|null;state:'in_stock'|'reserved'|'issued'|'installed'|'in_repair'|'written_off'|'lost';location_id:string|null;holder_id:string|null;installed_on:string|null};
export type WStock={item_id:string;item_name:string;unit:string;location_id:string;quantity:number;reserved:number};
export type WMovement={movement_id:string;kind:'receive'|'issue'|'return'|'transfer'|'repair_out'|'repair_in'|'install'|'remove'|'write_off'|'adjust'|'reverse';act_no:string;occurred_at:string;actor_ref:string;actor_name:string|null;basis:string;note:string|null;from_location:string|null;to_location:string|null;from_holder:string|null;to_holder:string|null;asset_uid:string|null;reverses:string|null;compat_override:boolean;lines:{line_no:number;item_id:string;item_name:string;unit:string;unit_id:string|null;serial:string|null;inventory_no:string|null;quantity:number}[]|null};
export type WReservation={reservation_id:string;unit_id:string|null;item_id:string|null;location_id:string|null;quantity:number|null;holder_id:string;basis:string;expires_at:string;state:'active'|'fulfilled'|'cancelled'|'expired';created_by:string;created_at:string;label:string};
export type WInventory={inventory_id:string;location_id:string;act_no:string;basis:string;state:'open'|'closed'|'cancelled';started_at:string;started_by:string;closed_at:string|null;shortage_movement:string|null;surplus_movement:string|null};
export type WInventoryDetail=WInventory&{lines:{item_id:string;item_name:string;unit:string;unit_id:string|null;serial:string|null;expected:number;counted:number|null;result:'ok'|'shortage'|'surplus'|'elsewhere';where:string|null}[]};
export type WOperation={kind:Exclude<WMovement['kind'],'adjust'|'reverse'>;basis:string;note?:string;from_location?:string;to_location?:string;from_holder?:string;to_holder?:string;asset_uid?:string;reservation_id?:string;compat_override?:boolean;lines:{unit_id?:string;item_id?:string;quantity?:number;serial?:string;inventory_no?:string}[]};
export type TicketKind='incident'|'request'|'change'|'problem';
export type Ticket={ticket_id:string;kind:TicketKind;number:string;title:string;description:string;impact:number;urgency:number;priority:number;state:string;requester_id:string|null;assignee_id:string|null;team_id:string|null;resolution:string|null;workaround:string|null;reopen_count:number;created_by:string;created_at:string;updated_at:string;resolved_at:string|null;closed_at:string|null;revision:string;sla:SlaTimer[]};
export type SlaTimer={metric:'response'|'resolution';target_minutes:number;elapsed_minutes:number;status:'running'|'paused'|'warning'|'breached'|'met'|'missed';due_at:string|null;warned_at:string|null;breached_at:string|null};
export type SlaSettings={hours:{timezone:string;days:number[];start_minute:number;end_minute:number;warn_percent:number};policies:{kind:'incident'|'request';priority:number;response_minutes:number;resolution_minutes:number}[];revision:string};
export type TicketDetail=Ticket&{allowed_transitions:string[];links:{target_kind:'asset'|'service'|'ticket'|'movement';target_id:string;label:string}[];events:{event_id:string;kind:string;public:boolean;detail:Record<string,unknown>;text:string|null;actor_ref:string;occurred_at:string}[];workarounds:string[];request:TicketRequest|null;change:TicketChange|null};
export type ChangeWindow={starts_at:string;ends_at:string;risk:'low'|'medium'|'high';plan:string;rollback_plan:string;conflicts_confirmed:boolean};
export type TicketChange={window:ChangeWindow|null;approval:TicketRequest['approval'];conflicts:{ticket_id:string;number:string;title:string;state:string;starts_at:string;ends_at:string}[]};
export type CalendarEntry={ticket_id:string;number:string;title:string;state:string;risk:ChangeWindow['risk'];starts_at:string;ends_at:string;targets:{target_kind:string;target_id:string;label:string}[]};
export type CatalogField={key:string;label:string;type:'text'|'textarea'|'select';required:boolean;options:string[]};
export type CatalogItem={item_id:string;name:string;description:string;form:CatalogField[];approver_id:string|null;team_id:string|null;warehouse_item_id:string|null;active:boolean;revision:string};
export type TicketRequest={catalog_item_id:string;catalog_name:string;form_values:Record<string,string>;approver_id:string|null;warehouse_item_id:string|null;approval:{approver_id:string|null;decision:'approved'|'rejected';comment:string|null;decided_by:string;decided_at:string}|null};
export type AssetPresence={asset_uid:string;miss_after:number;state:'present'|'missing'|'unknown';items:{network_id:string;network_name:string;ip:string;state:'present'|'missing';misses:number;first_seen:string;last_seen:string;missing_since:string|null}[]};
export type DiscoveryHostEvent={ip:string;kind:'appeared'|'missing'|'returned';run_id:string;at:string};
export type CollectKind='ssh'|'winrm'|'snmp';
export type CollectCredential={credential_id:string;name:string;kind:CollectKind;username:string;active:boolean;revision:string;secret_changed_at:string;targets:number;public_key:string|null};
export type CollectSecret={password?:string;private_key?:string;passphrase?:string;auth_protocol?:string;auth_key?:string;priv_protocol?:string;priv_key?:string;generate?:boolean};
export type WinRMTrust={configured:boolean;revision:string;updated_at:string|null;certificates:{subject:string;issuer:string;not_after:string;sha256:string}[];targets:number};
export type RemoteTarget={target_id:string;collector_id:string;network_id:string|null;address:string;kind:CollectKind;port:number;credential_id:string;host_key_sha256:string|null;host_key_origin:'admin'|'first_use'|null;tls_server_name:string|null;tls_cert_sha256:string|null;tls_cert_origin:'admin'|'domain_ca'|'first_use'|null;winrm_transport:'https'|'http_kerberos'|null;collect_requested_at:string|null;interval_seconds:number;agent_source_id:string|null;state:'pending'|'active'|'disabled';last_collected_at:string|null;last_error:string|null;revision:string};
export const api={
 login:(username:string,password:string)=>call<Session>('/api/v1/auth/sessions','Session',{method:'POST',body:JSON.stringify({username,password})}),
 logout:(csrf:string)=>call<void>('/api/v1/auth/session',undefined,{method:'DELETE',headers:{'X-CSRF-Token':csrf}}),
 assets:(cursor:string|null=null)=>call<AssetPage>('/api/v1/assets?limit=50'+(cursor?'&cursor='+encodeURIComponent(cursor):''),'AssetPage'),
 asset:(uid:string)=>call<Asset>('/api/v1/assets/'+encodeURIComponent(uid),'Asset'),
 inventory:(uid:string)=>call<InventoryDetail>('/api/v1/assets/'+encodeURIComponent(uid)+'/inventory','InventoryDetail'),
 profile:(source:string)=>call<SourceProfile>('/api/v1/sources/'+encodeURIComponent(source)+'/profile','SourceProfile'),
 records12:(uid:string,section:string,cursor:string|null=null)=>call<RecordPage12>('/api/v1/assets/'+encodeURIComponent(uid)+'/inventory/facts/'+encodeURIComponent(section)+'?limit=100'+(cursor?'&cursor='+encodeURIComponent(cursor):''),'RecordFactPage12'),
 conflicts:(state:string,cursor:string|null=null)=>call<ConflictPage>('/api/v1/reconciliation/conflicts?state='+encodeURIComponent(state)+'&limit=50'+(cursor?'&cursor='+encodeURIComponent(cursor):''),'ConflictPage'),
 resolveConflict:(id:string,csrf:string,body:{action:string;asset_uid?:string;revision?:string})=>call<ConflictResult>('/api/v1/reconciliation/conflicts/'+encodeURIComponent(id)+'/resolve','ConflictResult',{method:'POST',body:JSON.stringify(body),headers:{'X-CSRF-Token':csrf}}),
 wLocations:()=>call<{items:WLocation[]}>('/api/v1/warehouse/locations','WLocationList'),
 wItems:()=>call<{items:WItem[]}>('/api/v1/warehouse/items','WItemList'),
 wUnits:(f:{state?:string;holder?:string;location?:string;asset?:string;q?:string})=>{const q=new URLSearchParams(Object.entries(f).filter(([,v])=>v) as [string,string][]).toString();return call<{items:WUnit[]}>('/api/v1/warehouse/units'+(q?'?'+q:''),'WUnitList')},
 wStock:(location:string)=>call<{items:WStock[]}>('/api/v1/warehouse/stock'+(location?'?location='+encodeURIComponent(location):''),'WStockList'),
 wMovements:(f:{asset?:string;unit?:string}={})=>{const q=new URLSearchParams(Object.entries(f).filter(([,v])=>v) as [string,string][]).toString();return call<{items:WMovement[]}>('/api/v1/warehouse/movements'+(q?'?'+q:''),'WMovementList')},
 wMovement:(id:string)=>call<WMovement>('/api/v1/warehouse/movements/'+encodeURIComponent(id),'WMovement'),
 wMove:(csrf:string,op:WOperation)=>call<WMovement>('/api/v1/warehouse/movements','WMovement',{method:'POST',body:JSON.stringify(op),headers:{'X-CSRF-Token':csrf}}),
 wReverse:(csrf:string,id:string,basis:string)=>call<WMovement>('/api/v1/warehouse/movements/'+encodeURIComponent(id)+'/reverse','WMovement',{method:'POST',body:JSON.stringify({basis}),headers:{'X-CSRF-Token':csrf}}),
 wReservations:()=>call<{items:WReservation[]}>('/api/v1/warehouse/reservations','WReservationList'),
 wReserve:(csrf:string,b:{unit_id?:string;item_id?:string;location_id?:string;quantity?:number;holder_id:string;basis:string;expires_at:string})=>call<WReservation>('/api/v1/warehouse/reservations','WReservation',{method:'POST',body:JSON.stringify(b),headers:{'X-CSRF-Token':csrf}}),
 wCancelReservation:(csrf:string,id:string)=>call<WReservation>('/api/v1/warehouse/reservations/'+encodeURIComponent(id)+'/cancel','WReservation',{method:'POST',body:'{}',headers:{'X-CSRF-Token':csrf}}),
 wInventories:()=>call<{items:WInventory[]}>('/api/v1/warehouse/inventories','WInventoryList'),
 wInventory:(id:string)=>call<WInventoryDetail>('/api/v1/warehouse/inventories/'+encodeURIComponent(id),'WInventoryDetail'),
 wStartInventory:(csrf:string,location_id:string,basis:string)=>call<WInventoryDetail>('/api/v1/warehouse/inventories','WInventoryDetail',{method:'POST',body:JSON.stringify({location_id,basis}),headers:{'X-CSRF-Token':csrf}}),
 wCount:(csrf:string,id:string,b:{serials:{item_id:string;serial:string}[];quantities:{item_id:string;quantity:number}[]})=>call<WInventoryDetail>('/api/v1/warehouse/inventories/'+encodeURIComponent(id)+'/count','WInventoryDetail',{method:'PUT',body:JSON.stringify(b),headers:{'X-CSRF-Token':csrf}}),
 wInventoryAction:(csrf:string,id:string,verb:'close'|'cancel')=>call<WInventoryDetail>('/api/v1/warehouse/inventories/'+encodeURIComponent(id)+'/'+verb,'WInventoryDetail',{method:'POST',body:'{}',headers:{'X-CSRF-Token':csrf}}),
 wSetCompatibility:(csrf:string,item:string,models:string[])=>call<WItem>('/api/v1/warehouse/items/'+encodeURIComponent(item)+'/compatibility','WItem',{method:'PUT',body:JSON.stringify({compatible_models:models}),headers:{'X-CSRF-Token':csrf}}),
 wCompatibility:(item:string,asset:string)=>call<{compatible:boolean|null;asset_model:string}>('/api/v1/warehouse/compatibility?item='+encodeURIComponent(item)+'&asset='+encodeURIComponent(asset),'WCompatibility'),
 wCreateLocation:(csrf:string,b:{site_id:string;kind:WLocation['kind'];name:string;parent_id?:string})=>call<WLocation>('/api/v1/warehouse/locations','WLocation',{method:'POST',body:JSON.stringify(b),headers:{'X-CSRF-Token':csrf}}),
 wCreateItem:(csrf:string,b:{name:string;kind:WItem['kind'];unit:string;category?:string})=>call<WItem>('/api/v1/warehouse/items','WItem',{method:'POST',body:JSON.stringify(b),headers:{'X-CSRF-Token':csrf}}),
 portalLogin:(login:string,password:string)=>call<{user_id:string;tenant_id:string;roles:['requester'];expires_at:string;csrf_token:string}>('/api/v1/auth/directory-sessions','PortalSession',{method:'POST',body:JSON.stringify({login,password})}),
 sla:()=>call<SlaSettings>('/api/v1/itsm/sla','SLASettings'),
 saveSla:(csrf:string,b:SlaSettings)=>call<SlaSettings>('/api/v1/itsm/sla','SLASettings',{method:'PUT',body:JSON.stringify(b),headers:{'X-CSRF-Token':csrf}}),
 changeCalendar:(from:string,to:string)=>call<{items:CalendarEntry[]}>('/api/v1/itsm/changes/calendar?from='+encodeURIComponent(from)+'&to='+encodeURIComponent(to),'CalendarList'),
 catalog:()=>call<{items:CatalogItem[]}>('/api/v1/itsm/catalog','CatalogList'),
 saveCatalog:(csrf:string,b:Omit<CatalogItem,'item_id'|'revision'>&{revision?:string},id?:string)=>call<CatalogItem>('/api/v1/itsm/catalog'+(id?'/'+encodeURIComponent(id):''),'CatalogItem',{method:'POST',body:JSON.stringify(b),headers:{'X-CSRF-Token':csrf}}),
 portalCatalog:()=>call<{items:CatalogItem[]}>('/api/v1/portal/catalog','CatalogList'),
 portalRequest:(csrf:string,b:{catalog_item_id:string;form_values:Record<string,string>;urgency:number})=>call<TicketDetail>('/api/v1/portal/requests','TicketDetail',{method:'POST',body:JSON.stringify(b),headers:{'X-CSRF-Token':csrf}}),
 portalApprovals:()=>call<{items:Ticket[]}>('/api/v1/portal/approvals','TicketList'),
 portalApprove:(csrf:string,id:string,b:{revision:string;approve:boolean;comment:string})=>call<TicketDetail>('/api/v1/portal/tickets/'+encodeURIComponent(id)+'/approve','TicketDetail',{method:'POST',body:JSON.stringify(b),headers:{'X-CSRF-Token':csrf}}),
 portalTickets:()=>call<{items:Ticket[]}>('/api/v1/portal/tickets','TicketList'),
 portalTicket:(id:string)=>call<TicketDetail>('/api/v1/portal/tickets/'+encodeURIComponent(id),'TicketDetail'),
 portalCreate:(csrf:string,b:{title:string;description:string;urgency:number})=>call<TicketDetail>('/api/v1/portal/tickets','TicketDetail',{method:'POST',body:JSON.stringify(b),headers:{'X-CSRF-Token':csrf}}),
 portalAction:(csrf:string,id:string,action:'comments'|'confirm',b:Record<string,unknown>)=>call<TicketDetail>('/api/v1/portal/tickets/'+encodeURIComponent(id)+'/'+action,'TicketDetail',{method:'POST',body:JSON.stringify(b),headers:{'X-CSRF-Token':csrf}}),
 tickets:(f:{kind?:string;state?:string;mine?:boolean;q?:string})=>{const q=new URLSearchParams();if(f.kind)q.set('kind',f.kind);if(f.state)q.set('state',f.state);if(f.mine)q.set('mine','true');if(f.q)q.set('q',f.q);const qs=q.toString();return call<{items:Ticket[]}>('/api/v1/itsm/tickets'+(qs?'?'+qs:''),'TicketList')},
 ticket:(id:string)=>call<TicketDetail>('/api/v1/itsm/tickets/'+encodeURIComponent(id),'TicketDetail'),
 createTicket:(csrf:string,b:{kind:TicketKind;title:string;description:string;impact:number;urgency:number;requester_id?:string;asset_uid?:string;service_uid?:string})=>call<TicketDetail>('/api/v1/itsm/tickets','TicketDetail',{method:'POST',body:JSON.stringify(b),headers:{'X-CSRF-Token':csrf}}),
 ticketAction:(csrf:string,id:string,action:'transition'|'assign'|'comments'|'links'|'approve'|'fulfill'|'window',b:Record<string,unknown>)=>call<TicketDetail>('/api/v1/itsm/tickets/'+encodeURIComponent(id)+'/'+action,'TicketDetail',{method:'POST',body:JSON.stringify(b),headers:{'X-CSRF-Token':csrf}}),
 assetPresence:(uid:string)=>call<AssetPresence>('/api/v1/assets/'+encodeURIComponent(uid)+'/presence','AssetPresence'),
 sourceRecords:(uid:string)=>call<SourceRecordPage>('/api/v1/assets/'+encodeURIComponent(uid)+'/source-records','SourceRecordPage'),
 mergeAssets:(csrf:string,body:{target_asset_uid:string;absorbed_asset_uid:string;target_version?:string})=>call<AssetOperation>('/api/v1/assets/merge','AssetOperation',{method:'POST',body:JSON.stringify(body),headers:{'X-CSRF-Token':csrf},signal:AbortSignal.timeout(130000)}),
 splitAsset:(uid:string,csrf:string,body:{source_record_keys:string[];target_asset_uid?:string;version?:string})=>call<AssetOperation>('/api/v1/assets/'+encodeURIComponent(uid)+'/split','AssetOperation',{method:'POST',body:JSON.stringify(body),headers:{'X-CSRF-Token':csrf},signal:AbortSignal.timeout(130000)}),
 registrationCodes:()=>call<{items:RegistrationCode[];center_fingerprint:string}>('/api/v1/registration-codes','RegistrationCodeList'),
 createRegistrationCode:(csrf:string,b:{source_kind:'agent'|'collector';site_id:string;collector_source_id?:string;inventory_platform?:string;max_uses:number;ttl_hours:number;comment:string})=>call<RegistrationCode>('/api/v1/registration-codes','RegistrationCode',{method:'POST',body:JSON.stringify(b),headers:{'X-CSRF-Token':csrf}}),
 revokeRegistrationCode:(csrf:string,id:string)=>call<RegistrationCode>('/api/v1/registration-codes/'+encodeURIComponent(id)+'/revoke','RegistrationCode',{method:'POST',body:'{}',headers:{'X-CSRF-Token':csrf}}),
 registrationUses:(id:string)=>call<{items:{source_id:string;hostname:string;registered_at:string}[]}>('/api/v1/registration-codes/'+encodeURIComponent(id)+'/uses','RegistrationUseList'),
 portableScopes:()=>call<{tenant_id:string;items:PortableScope[];encryption:PortableEncryption|null;encryption_available:boolean}>('/api/v1/sources/portable-scopes','PortableScopeList'),
 enablePortableEncryption:(csrf:string)=>call<PortableEncryption>('/api/v1/sources/portable-encryption','PortableEncryption',{method:'POST',body:'{}',headers:{'X-CSRF-Token':csrf}}),
 registerPortable:(csrf:string,body:{site_id:string;scope_id:string;source_id:string;generation_id:string;public_key:string})=>call<{source_id:string;key_id:string}>('/api/v1/sources/portable','PortableRegistered',{method:'POST',body:JSON.stringify(body),headers:{'X-CSRF-Token':csrf}}),
 importPortable:(csrf:string,source:string,file:File)=>call<PortableReport>('/api/v1/sources/'+encodeURIComponent(source)+'/portable-import','PortableReport',{method:'POST',body:file,signal:AbortSignal.timeout(300000),headers:{'Content-Type':'application/zip','X-CSRF-Token':csrf}}),
 retireAsset:(uid:string,csrf:string,reason:string)=>call<AssetCMDB>('/api/v1/assets/'+encodeURIComponent(uid)+'/retire','AssetCMDB',{method:'POST',body:JSON.stringify({reason}),headers:{'X-CSRF-Token':csrf}}),
 restoreAsset:(uid:string,csrf:string)=>call<AssetCMDB>('/api/v1/assets/'+encodeURIComponent(uid)+'/restore','AssetCMDB',{method:'POST',body:'{}',headers:{'X-CSRF-Token':csrf}}),
 retiredAssets:()=>call<{tenant_id:string;items:RetiredAsset[]}>('/api/v1/retired-assets','RetiredAssetList'),
 assetCMDB:(uid:string)=>call<AssetCMDB>('/api/v1/assets/'+encodeURIComponent(uid)+'/cmdb','AssetCMDB'),
 setAssetClass:(uid:string,csrf:string,body:{asset_class:AssetClassName|null;revision:string})=>call<AssetCMDB>('/api/v1/assets/'+encodeURIComponent(uid)+'/classification','AssetCMDB',{method:'PATCH',body:JSON.stringify(body),headers:{'X-CSRF-Token':csrf}}),
 software:(uid:string,filter:string,cursor:string|null)=>call<SoftwarePage>('/api/v1/assets/'+encodeURIComponent(uid)+'/software?limit=100'+(filter?'&filter='+encodeURIComponent(filter):'')+(cursor?'&cursor='+encodeURIComponent(cursor):''),'SoftwarePage'),
 components:(uid:string)=>call<ComponentList>('/api/v1/assets/'+encodeURIComponent(uid)+'/components','ComponentList'),
 products:(q:string)=>call<ProductList>('/api/v1/software?q='+encodeURIComponent(q),'ProductList'),
 services:(cursor:string|null=null)=>call<ServicePage>('/api/v1/services?limit=50'+(cursor?'&cursor='+encodeURIComponent(cursor):''),'ServicePage'),
 service:(uid:string)=>call<ServiceDetail>('/api/v1/services/'+encodeURIComponent(uid),'ServiceDetail'),
 createService:(csrf:string,body:{name:string;description?:string;criticality?:string})=>call<ServiceDetail>('/api/v1/services','ServiceDetail',{method:'POST',body:JSON.stringify(body),headers:{'X-CSRF-Token':csrf}}),
 patchService:(uid:string,csrf:string,body:{revision:string;name?:string;description?:string;criticality?:string;retire?:boolean})=>call<ServiceDetail>('/api/v1/services/'+encodeURIComponent(uid),'ServiceDetail',{method:'PATCH',body:JSON.stringify(body),headers:{'X-CSRF-Token':csrf}}),
 createRelation:(csrf:string,body:{relation_type:string;from:CIEnd;to:CIEnd;note?:string})=>call<Relation>('/api/v1/relations','Relation',{method:'POST',body:JSON.stringify(body),headers:{'X-CSRF-Token':csrf}}),
 retireRelation:(id:string,csrf:string)=>call<Relation>('/api/v1/relations/'+encodeURIComponent(id),'Relation',{method:'DELETE',headers:{'X-CSRF-Token':csrf}}),
 enableWebhooks:(csrf:string)=>call<WebhookList>('/api/v1/webhooks/enable','WebhookList',{method:'POST',body:'{}',headers:{'X-CSRF-Token':csrf}}),
 directorySettings:()=>call<DirectorySettingsView>('/api/v1/directory-sync/settings','DirectorySettingsView'),
 saveDirectorySettings:(csrf:string,body:{revision:string;settings:DirectoryWebSettings;password?:string})=>call<DirectorySettingsView>('/api/v1/directory-sync/settings','DirectorySettingsView',{method:'PUT',body:JSON.stringify(body),headers:{'X-CSRF-Token':csrf}}),
 deleteDirectorySettings:(csrf:string,revision:string)=>call<void>('/api/v1/directory-sync/settings?revision='+encodeURIComponent(revision),undefined,{method:'DELETE',headers:{'X-CSRF-Token':csrf}}),
 testDirectory:(csrf:string,body:{revision:string;settings:DirectoryWebSettings;password?:string})=>call<DirectoryTestResult>('/api/v1/directory-sync/test','DirectoryTestResult',{method:'POST',body:JSON.stringify(body),headers:{'X-CSRF-Token':csrf},signal:AbortSignal.timeout(120000)}),
 winrmTrust:()=>call<WinRMTrust>('/api/v1/discovery/winrm-ca','WinRMTrust'),
 setWinrmTrust:(csrf:string,revision:string,ca_pem:string|null)=>call<WinRMTrust>('/api/v1/discovery/winrm-ca','WinRMTrust',{method:'PUT',body:JSON.stringify({revision,ca_pem}),headers:{'X-CSRF-Token':csrf}}),
 collectCredentials:()=>call<{items:CollectCredential[];secrets_available:boolean}>('/api/v1/discovery/credentials','CollectCredentialPage'),
 createCollectCredential:(csrf:string,body:{name:string;kind:CollectKind;username:string;secret:CollectSecret})=>call<CollectCredential>('/api/v1/discovery/credentials','CollectCredential',{method:'POST',body:JSON.stringify(body),headers:{'X-CSRF-Token':csrf}}),
 patchCollectCredential:(id:string,csrf:string,body:{revision:string;active?:boolean;secret?:CollectSecret})=>call<CollectCredential>('/api/v1/discovery/credentials/'+encodeURIComponent(id),'CollectCredential',{method:'PATCH',body:JSON.stringify(body),headers:{'X-CSRF-Token':csrf}}),
 remoteTargets:()=>call<{items:RemoteTarget[]}>('/api/v1/discovery/targets','RemoteTargetPage'),
 createRemoteTarget:(csrf:string,body:{collector_id:string;network_id?:string;address:string;kind:CollectKind;port?:number;credential_id:string;host_key_sha256?:string;tls_ca_pem?:string;tls_server_name?:string;tls_trust?:'first_use'|'domain_ca';winrm_transport?:'https'|'http_kerberos';interval_seconds?:number})=>call<RemoteTarget>('/api/v1/discovery/targets','RemoteTarget',{method:'POST',body:JSON.stringify(body),headers:{'X-CSRF-Token':csrf}}),
 collectTargetNow:(id:string,csrf:string)=>call<RemoteTarget>('/api/v1/discovery/targets/'+encodeURIComponent(id)+'/collect','RemoteTarget',{method:'POST',body:'{}',headers:{'X-CSRF-Token':csrf}}),
 patchRemoteTarget:(id:string,csrf:string,body:{revision:string;disabled:boolean;reset_host_key?:boolean;reset_tls_cert?:boolean})=>call<RemoteTarget>('/api/v1/discovery/targets/'+encodeURIComponent(id),'RemoteTarget',{method:'PATCH',body:JSON.stringify(body),headers:{'X-CSRF-Token':csrf}}),
 discoveryNetworks:()=>call<DiscoveryNetworkPage>('/api/v1/discovery/networks','DiscoveryNetworkPage'),
 createDiscoveryNetwork:(csrf:string,body:{site_id:string;collector_id:string;name:string;cidr:string;probes:DiscoveryProbe[];schedule_minutes:number|null})=>call<DiscoveryNetwork>('/api/v1/discovery/networks','DiscoveryNetwork',{method:'POST',body:JSON.stringify(body),headers:{'X-CSRF-Token':csrf}}),
 patchDiscoveryNetwork:(id:string,csrf:string,body:{revision:string;name?:string;probes?:DiscoveryProbe[];schedule_minutes?:number;active?:boolean})=>call<DiscoveryNetwork>('/api/v1/discovery/networks/'+encodeURIComponent(id),'DiscoveryNetwork',{method:'PATCH',body:JSON.stringify(body),headers:{'X-CSRF-Token':csrf}}),
 startDiscovery:(id:string,csrf:string)=>call<{run_id:string;state:'queued'}>('/api/v1/discovery/networks/'+encodeURIComponent(id)+'/runs','DiscoveryRunStarted',{method:'POST',body:'{}',headers:{'X-CSRF-Token':csrf}}),
 discoveryRuns:(id:string)=>call<{items:DiscoveryRun[]}>('/api/v1/discovery/networks/'+encodeURIComponent(id)+'/runs','DiscoveryRunPage'),
 discoveryHosts:(id:string)=>call<{items:DiscoveryHost[]}>('/api/v1/discovery/networks/'+encodeURIComponent(id)+'/hosts','DiscoveryHostPage'),
 cancelDiscovery:(id:string,run:string,csrf:string)=>call<{run_id:string;state:'failed'}>('/api/v1/discovery/networks/'+encodeURIComponent(id)+'/runs/'+encodeURIComponent(run)+'/cancel',undefined,{method:'POST',body:'{}',headers:{'X-CSRF-Token':csrf}}),
 discoveryEvents:(id:string)=>call<{items:DiscoveryHostEvent[]}>('/api/v1/discovery/networks/'+encodeURIComponent(id)+'/events','DiscoveryHostEventList'),
 webhooks:()=>call<WebhookList>('/api/v1/webhooks','WebhookList'),
 createWebhook:(csrf:string,body:{url:string;event_types:WebhookEventType[]})=>call<WebhookCreated>('/api/v1/webhooks','WebhookCreated',{method:'POST',body:JSON.stringify(body),headers:{'X-CSRF-Token':csrf}}),
 patchWebhook:(id:string,csrf:string,body:{revision:string;active?:boolean})=>call<WebhookSubscription>('/api/v1/webhooks/'+encodeURIComponent(id),'WebhookSubscription',{method:'PATCH',body:JSON.stringify(body),headers:{'X-CSRF-Token':csrf}}),
 webhookDeliveries:(id:string,state:''|'pending'|'delivered'|'dead')=>call<WebhookDeliveryPage>('/api/v1/webhooks/'+encodeURIComponent(id)+'/deliveries'+(state?'?state='+state:''),'WebhookDeliveryPage'),
 retryWebhook:(id:string,event:string,csrf:string)=>call<void>('/api/v1/webhooks/'+encodeURIComponent(id)+'/deliveries/'+encodeURIComponent(event)+'/retry',undefined,{method:'POST',headers:{'X-CSRF-Token':csrf}}),
 directorySync:()=>call<DirectorySyncStatus>('/api/v1/directory-sync','DirectorySyncStatus'),
 runDirectorySync:(csrf:string,mode:'full'|'auto')=>call<SyncRun>('/api/v1/directory-sync/run','SyncRun',{method:'POST',body:JSON.stringify({mode}),headers:{'X-CSRF-Token':csrf},signal:AbortSignal.timeout(300000)}),
 importCSV:(csrf:string,text:string,dry:boolean)=>call<CSVImportResult>('/api/v1/assets/import.csv?dry_run='+dry,'CSVImportResult',{method:'POST',body:text,headers:{'X-CSRF-Token':csrf,'Content-Type':'text/csv; charset=utf-8'},signal:AbortSignal.timeout(300000)}),
 subjects:(kind:''|'person'|'team'='',inactive=false)=>call<SubjectPage>('/api/v1/subjects?limit=200'+(kind?'&kind='+kind:'')+(inactive?'&include_inactive=true':''),'SubjectPage'),
 createSubject:(csrf:string,body:{kind:'person'|'team';name:string;contact:string;username?:string})=>call<SubjectResult>('/api/v1/subjects','SubjectResult',{method:'POST',body:JSON.stringify(body),headers:{'X-CSRF-Token':csrf}}),
 patchSubject:(id:string,csrf:string,body:{revision:string;name?:string;contact?:string;username?:string;deactivate?:boolean;reactivate?:boolean})=>call<SubjectResult>('/api/v1/subjects/'+encodeURIComponent(id),'SubjectResult',{method:'PATCH',body:JSON.stringify(body),headers:{'X-CSRF-Token':csrf}}),
 member:(team:string,person:string,csrf:string,add:boolean)=>call<Subject>('/api/v1/subjects/'+encodeURIComponent(team)+'/members/'+encodeURIComponent(person),'Subject',{method:add?'PUT':'DELETE',headers:{'X-CSRF-Token':csrf}}),
 assignments:(uid:string)=>call<AssetAssignments>('/api/v1/assets/'+encodeURIComponent(uid)+'/assignments','AssetAssignments'),
 assign:(uid:string,csrf:string,body:{role:RoleName;subject_id:string|null;note?:string;expected_version:string})=>call<AssetAssignments>('/api/v1/assets/'+encodeURIComponent(uid)+'/assignments','AssetAssignments',{method:'POST',body:JSON.stringify(body),headers:{'X-CSRF-Token':csrf}}),
 bulkAssign:(csrf:string,body:{role:RoleName;subject_id:string;note?:string;items:{asset_uid:string;expected_version:string}[]})=>call<BulkAssignResult>('/api/v1/assignments/bulk','BulkAssignResult',{method:'POST',body:JSON.stringify(body),headers:{'X-CSRF-Token':csrf}}),
 worklist:(scope:string,cursor:string|null=null)=>call<WorklistPage>('/api/v1/worklist?limit=100&scope='+encodeURIComponent(scope)+(cursor?'&cursor='+encodeURIComponent(cursor):''),'WorklistPage'),
 search:(q:string,filters:{os?:string;class?:string},cursor:string|null)=>call<SearchPage>('/api/v1/search?limit=20&q='+encodeURIComponent(q)+(filters.os?'&os='+encodeURIComponent(filters.os):'')+(filters.class?'&class='+encodeURIComponent(filters.class):'')+(cursor?'&cursor='+encodeURIComponent(cursor):''),'SearchPage'),
 topology:()=>call<Topology>('/api/v1/topology','Topology'),
 networkMap:()=>call<NetworkMap>('/api/v1/topology/map','NetworkMap'),
 saveNetworkMap:(csrf:string,revision:string,document:MapDocument)=>call<NetworkMap>('/api/v1/topology/map','NetworkMap',{method:'PUT',body:JSON.stringify({revision,document}),headers:{'X-CSRF-Token':csrf}}),
 sources:(cursor:string|null=null)=>call<SourcePage>('/api/v1/sources?limit=50'+(cursor?'&cursor='+encodeURIComponent(cursor):''),'SourcePage')
};
export async function checkCompatibility(){
 try{
 const [manifest,contract,extension]=await Promise.all([fetch('/version.json',{cache:'no-store'}),fetch('/contracts/openapi.json',{cache:'no-store'}),fetch('/contracts/c09.openapi.json',{cache:'no-store'})]);
 if(!manifest.ok||!contract.ok||!extension.ok)throw new Error();
 const version=await manifest.json() as {wire?:{major:number;minor:number};openapi_sha256?:string;c09_version?:string;c09_sha256?:string};
 async function digest(response:Response){const bytes=await response.arrayBuffer();if(bytes.byteLength>1048576)throw new Error();return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),n=>n.toString(16).padStart(2,'0')).join('')}
 if(version.wire?.major!==1||version.wire?.minor!==0||version.c09_version!=='1.0'||version.openapi_sha256!==await digest(contract)||version.c09_sha256!==await digest(extension))throw new Error();
 }catch{throw new ApiError(0,'CONTRACT_MISMATCH')}
}
