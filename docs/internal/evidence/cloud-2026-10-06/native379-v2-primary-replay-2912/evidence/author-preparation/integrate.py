from pathlib import Path
r=Path('/workspace/.zasp-cloud-owned/native379-v2-primary-replay-ci9zftl1');p=r/'source/services/platform/apiserver/authorization_worker_ordered_current_native379_v2_test.go';s=p.read_text()
s=s.replace('type orderedCurrentNative379V2CatalogDiagnostic struct {','type orderedCurrentNative379V2CatalogDiagnostic struct {\n Replay *native379V2PrimaryReplay `json:"replay,omitempty"`')
s=s.replace('func orderedCurrentNative379V2InstallAndCompare(ctx context.Context, owner *pgx.Conn, admission orderedCurrentNative379V2AdmittedPacket, module, manifest, collector []byte) (orderedCurrentNative379V2Observation, error) {\n\tvar observation orderedCurrentNative379V2Observation','func orderedCurrentNative379V2InstallAndCompare(ctx context.Context, owner *pgx.Conn, admission orderedCurrentNative379V2AdmittedPacket, module, manifest, collector []byte) (observation orderedCurrentNative379V2Observation, returnedErr error) {')
s=s.replace('recorder := &orderedCurrentNative379V2OperationRecorder{}\n\tif err := orderedCurrentNative379V2Preinstall', '''recorder := native379V2NewPristineRecorder(ctx,packet,nil)
 defer func(){
  if returnedErr==nil {return}
  raw,err:=json.Marshal(recorder.safePrefix())
  if err!=nil || len(raw)>65536 {returnedErr=errors.New("native379 pristine failure prefix refused");return}
  returnedErr=fmt.Errorf("%w: pristineCompletionPrefix=%s",returnedErr,raw)
 }()
 if err := orderedCurrentNative379V2Preinstall''')
s=s.replace('''if !catalog {
		diagnostic := orderedCurrentNative379V2CollectCatalogDiagnostic(ctx, tx, packet, collector)
		return orderedCurrentNative379V2Observation{}, orderedCurrentNative379V2CatalogFailure(diagnostic)
	}''','''if !catalog {
  replay:=native379V2RunPrimaryReplay(ctx,module,packet.Entry.Manifest,int32(owner.PgConn().PID()),owner.Config().User,func(queryCtx context.Context,sql string,args ...any)(bool,error){
   var value bool;err:=tx.QueryRow(queryCtx,sql,args...).Scan(&value);return value,err
  })
  // A replay refusal is additional evidence, never the original branch trace or
  // authorization. It avoids repeating the expensive collector after proof of
  // an earlier prefix refusal, while the primary result remains rejected.
  if replay.Outcome=="observed-prefix-refusal" || replay.Outcome=="replay-session-frame-refusal" {
   raw,err:=json.Marshal(replay);if err!=nil||len(raw)>65536{return observation,errors.New("native379 replay diagnostic refusal")}
   return observation,fmt.Errorf("native379 primary catalog returned false; incomplete replay diagnostic=%s",raw)
  }
  diagnostic := orderedCurrentNative379V2CollectCatalogDiagnostic(ctx, tx, packet, collector)
  diagnostic.Replay=&replay
  return orderedCurrentNative379V2Observation{}, orderedCurrentNative379V2CatalogFailure(diagnostic)
 }''')
old='return fmt.Errorf("native379 server or pgcrypto identity refused: query=%v server=%d want_server=%d postgres=%q want_postgres=%q pgcrypto=%q want_pgcrypto=%q address=%q port=%d", recorderErr, server, packet.Identity.ServerVersionNum, postgres, packet.Identity.Postgres, pgcrypto, packet.Identity.Pgcrypto, address, port)'
s=s.replace(old,'return errors.New("native379 server or pgcrypto identity refused")')
p.write_text(s)
